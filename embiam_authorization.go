package embiam

import (
	"fmt"
	"log"
)

// initializeAuthorization initializes the authorization sub system
func initializeAuthorizations() {
	// load roles
	roleCache = RoleCacheMap{}
	ReadRoles()
	if roleCache == nil {
		roleCache = RoleCacheMap{}
	}
	if len(roleCache) == 0 {
		log.Println("No roles loaded. Using minimal default roles")
		// create example roleMap
		roleCache = RoleCacheMap{
			"embiam": {
				Authorization: []AuthorizationStruct{{
					Ressource: "embiam",
					Action:    ActionMap{ActionAsteriks: {}},
				}},
				ContainedRole: []RoleIdType{},
			},
			`application`: {
				Authorization: []AuthorizationStruct{{
					Ressource: `application`,
					Action:    ActionMap{ActionAsteriks: {}},
				}},
				ContainedRole: []RoleIdType{},
			},
		}
	}
	// load default roles (for new entities)
	defaultRoles = []RoleIdType{}
	defaultRoles, _ = Db.readDefaultRoles()
	if defaultRoles == nil {
		defaultRoles = []RoleIdType{}
	}
	if len(defaultRoles) == 0 {
		defaultRoles = []RoleIdType{`application`}
	}

	// initialize authorization cache
	authorizationCache = AuthorizationCacheMap{}
}

/********************************************************************
	RESSOURCE

	A ressource in embiam is a thing that is relevant for
	authorization checks


	ACTION

	An Action is something that can be done with a ressource and
	shall be checked in terms of authorization


	AUTHORIZTION

	An authorization contains a RESSOURCE and a set of action for
	the ressource

*********************************************************************/

type (
	// RessourceType - a ressource is a thing that is relevant for authorization checks
	RessourceType string

	// ActionType - an activity can be performed on a recource and is relevant for authority checks
	ActionType string

	// ActionMap is a set of activities
	ActionMap map[ActionType]struct{}

	// AuthorizationStruct describes a ressource together with actitivies
	AuthorizationStruct struct {
		Ressource RessourceType `json:"ressource"`
		Action    ActionMap     `json:"action"`
	}
)

const ActionAsteriks ActionType = "*"

// contains checks if resA is equal to resB or resA has a * at the end and the prefixed of A and B are equal
func (resA RessourceType) contains(resB RessourceType) bool {
	if resA == resB {
		return true
	} else {
		// case resA="embiam.*" and resB="embiam.entity"
		if len(resA) == 0 {
			return false
		}
		l := len(resA) - 1
		if len(resB) < l {
			return false
		}
		if resA[l:] == "*" {
			return resA[0:l] == resB[0:l]
		}
		return false
	}
}

/********************************************************************
	ROLE CACHE

	ToDo...
*********************************************************************/
type (
	// RoleIdType - a role is a collection of Authorization with an Id
	// it can also contain other roles and forms a hierarchical structure of authorizations
	RoleIdType string
	// RoleBodyStruct contains authorizations contained in the role and also other roles
	RoleBodyStruct struct {
		Authorization []AuthorizationStruct `json:"authorization"`
		ContainedRole []RoleIdType          `json:"containedRoles"`
	}
	// RoleCacheMap combines the Id of the role with the role's body
	RoleCacheMap map[RoleIdType]RoleBodyStruct
)

var (
	roleCache    RoleCacheMap // all available roles
	defaultRoles []RoleIdType // roles automatically assigned to new user
)

// ReadRoles loads the roles newly from Db -- ToDo: Required???
func ReadRoles() error {
	var err error
	roleCache, err = Db.readRoles()
	if err != nil {
		return err
	}
	err = roleCache.checkConsistency()
	if err != nil {
		return err
	}
	return nil
}

// ReadDefaultRoles load the default roles from Db  -- ToDo: Required???
func ReadDefaultRoles() error {
	var err error
	defaultRoles, err = Db.readDefaultRoles()
	if err != nil {
		return err
	}
	return nil
}

// SaveRoles saves new roles -- ToDo: Required???
func SaveRoles(newRoles RoleCacheMap) error {
	// save
	err := Db.saveRoles(newRoles)
	if err != nil {
		return err
	}
	//update cache
	roleCache = newRoles
	return nil
}

// SaveDefaultRoles saves the default roles to Db -- ToDo: Required???
func SaveDefaultRoles(newDefaultRoles []RoleIdType) error {
	// save
	err := Db.saveDefaultRoles(newDefaultRoles)
	if err != nil {
		return err
	}
	// update cache
	defaultRoles = newDefaultRoles
	return nil
}

// getAuthorizationsForNick collects all authorizations from roles assigned to nick
func (r *RoleCacheMap) getAuthorizationsForEntity(entity *Entity) ([]AuthorizationStruct, error) {
	// collect authorizations from roles
	authorizations := []AuthorizationStruct{}
	for _, roleId := range entity.Roles {
		roleAuthorizations, err := r.getAuthorizationsFromRole(roleId)
		if err != nil {
			return nil, err
		}
		// ToDo: Merge authorizations!
		authorizations = append(authorizations, roleAuthorizations...)
	}

	return authorizations, nil
}

func (r RoleCacheMap) checkConsistency() error {
	cycleFreeRoles := make(map[RoleIdType]struct{})
	// iterate all roles
	for roleId, roleBody := range r {
		// check referencial integrity of contained roles
		for _, containedRoleId := range roleBody.ContainedRole {
			if _, ok := r[containedRoleId]; !ok {
				return fmt.Errorf("role %s contains undefined role %s", roleId, containedRoleId)
			}
		}
		// check current role for cycle
		path := new([]RoleIdType)
		if r.hasRoleCycle(roleId, &cycleFreeRoles, path) {
			return fmt.Errorf("role %s leads to cycle", roleId)
		}
	}
	return nil
}

// checks if roleId contains a cycle (see graph theorie, depth-first-search DFS)
func (r RoleCacheMap) hasRoleCycle(roleId RoleIdType, cycleFreeRoles *map[RoleIdType]struct{}, path *[]RoleIdType) bool {
	// check for cycle: if path contains roleId, a cycle is detected
	for _, pathRoleId := range *path { // improve for long paths
		if roleId == pathRoleId {
			return true
		}
	}
	// check each contained role, if it leads to a cycle
	hasCycle := false
	roleBody := r[roleId]
	if roleBody.ContainedRole == nil || len(roleBody.ContainedRole) == 0 {
		// current role doesn't contain any roles: register as cycle-free
		(*cycleFreeRoles)[roleId] = struct{}{}
	} else {
		// add current role to path
		*path = append(*path, roleId)
		// check contained roles for cycles
		for _, containedRoleId := range roleBody.ContainedRole {
			if r.hasRoleCycle(containedRoleId, cycleFreeRoles, path) {
				hasCycle = true
				break
			}
			// containedRoleId doesn't have a cycle: register as cycle-free
			(*cycleFreeRoles)[containedRoleId] = struct{}{}
		}
		// remove current role from path
		*path = (*path)[0 : len(*path)-1]
	}
	return hasCycle
}

// getAuthorizationsFromRole get all authorizations from a role
// direct authorizations that are part of the role itself and indirect authorizations
// from embedded roles
// If roleId doesn't exist an error is returned
func (r RoleCacheMap) getAuthorizationsFromRole(roleId RoleIdType) ([]AuthorizationStruct, error) {
	roleBody, ok := r[roleId]
	if !ok {
		return nil, fmt.Errorf("role '%s' doesn't exists", roleId)
	}
	// collect direct authorizations from role
	authorizations := []AuthorizationStruct{}
	authorizations = append(authorizations, roleBody.Authorization...)

	// colllect indirect authorizations from embedded roles
	for _, embeddedRoleId := range roleBody.ContainedRole {
		indirectAuthorizations, err := r.getAuthorizationsFromRole(embeddedRoleId)
		if err != nil {
			return authorizations, err
		}
		// collect indirect authorizations from embedded role
		authorizations = append(authorizations, indirectAuthorizations...)
	}
	// merge authorization (one record per ressource)
	return mergeAuthorizations(authorizations), nil
}

// mergeAuthorizations combines multiple actions on the same ressource in one record
// and makes sure that exactly one record exists per ressource
func mergeAuthorizations(inAuths []AuthorizationStruct) (outAuths []AuthorizationStruct) {
	outAuthMap := map[RessourceType]ActionMap{}
	// merge authorizations
	for _, inAuth := range inAuths {
		if outAuthMap[inAuth.Ressource] == nil {
			outAuthMap[inAuth.Ressource] = ActionMap{}
		}
		for inAuthAction := range inAuth.Action {
			outAuthMap[inAuth.Ressource][inAuthAction] = struct{}{}
		}
	}
	// convert outAuthMap to target data structure
	outAuths = []AuthorizationStruct{}
	for ressource, actionMap := range outAuthMap {
		outAuths = append(outAuths, AuthorizationStruct{
			Ressource: ressource,
			Action:    actionMap,
		})
	}
	return outAuths
}

/********************************************************************
	AUTHORIZATION CACHE

	ToDo...
*********************************************************************/
type (
	// AuthorizationCacheMap contains a Authorizations for nicks
	AuthorizationCacheMap map[string][]AuthorizationStruct
)

var authorizationCache AuthorizationCacheMap // authorizations of a nick
// ToDo: Add livetime managemnt - don't keep data of nick for ever

// AddNicksAuthorizationsToCache adds the authorizations of a nick to the authorization cache
func AddNicksAuthorizationsToCache(entity *Entity) error {
	authorizations, err := roleCache.getAuthorizationsForEntity(entity)
	if err != nil {
		return err
	}
	authorizationCache[entity.Nick] = authorizations
	return nil
}

// IsAuthorized checks if the entity, provided through token, is authorizied for action on ressource
func IsAuthorized(identityToken string, ressourceString string, actionString string) bool {
	// get nick from token
	nick := identityTokenCache.getNick(identityToken)
	if nick == "" {
		return false // invalid token
	}

	// get all authorizations of nick
	nickAuths, ok := authorizationCache[nick]
	if !ok {
		return false
	}
	// iterate nick's authorizations
	// ToDo: O(n) --> O(1) || O(log n)
	for _, auth := range nickAuths {
		// check if the authorization's ressources contains the requested ressource
		if auth.Ressource.contains(RessourceType(ressourceString)) {
			// check action
			_, ok := auth.Action[ActionType(actionString)]
			if ok {
				// nick has authorization for ressource and for action
				return true
			}
			_, ok = auth.Action[ActionAsteriks]
			if ok {
				// nick has authorization for ressource and for action *
				return true
			}
		}
	}
	return false
}
