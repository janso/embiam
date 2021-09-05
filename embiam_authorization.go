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

// ReadRoles loads the roles newly from Db
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

// ReadDefaultRoles loads the list of roles for new entities
func ReadDefaultRoles() error {
	var err error
	defaultRoles, err = Db.readDefaultRoles()
	if err != nil {
		return err
	}
	return nil
}

// SaveRoles loads the roles newly from Db
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

// SaveDefaultRoles loads the list of roles for new entities
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
	cycleFreeRoles := map[RoleIdType]struct{}{}
	// iterate all roles
	for roleId, roleBody := range r {
		// check referencial integrity of contained roles
		for _, containedRoleId := range roleBody.ContainedRole {
			if _, ok := r[containedRoleId]; !ok {
				return fmt.Errorf("role %s contains undefined role %s", roleId, containedRoleId)
			}
		}
		// check for cycle
		if _, ok := cycleFreeRoles[roleId]; ok {
			continue
		}
		// role doesn't have chilfren and can't lead to cycles
		if roleBody.ContainedRole == nil {
			cycleFreeRoles[roleId] = struct{}{}
			continue
		}
		// check current role if the contained roles lead to a cycle
		visitedRoles := map[RoleIdType]struct{}{}
		if !r.hasRoleCycle(roleId, cycleFreeRoles, visitedRoles) {
			// roleId creates no cycle - remember the checked roles to avoid duplicate checks
			for visitedRole := range visitedRoles {
				cycleFreeRoles[visitedRole] = struct{}{}
			}
		} else {
			return fmt.Errorf("child of role %s leads to cycle", roleId)
		}
	}
	return nil
}

func (r RoleCacheMap) hasRoleCycle(roleId RoleIdType, cycleFreeRoles, visitedRoles map[RoleIdType]struct{}) bool {
	if visitedRoles == nil {
		visitedRoles = map[RoleIdType]struct{}{}
	}
	if _, ok := visitedRoles[roleId]; ok {
		// cycle detected
		return true
	}

	// register current role as visited
	visitedRoles[roleId] = struct{}{}

	// check each contained role, if it leads to a cycle
	roleBody := r[roleId]
	if roleBody.ContainedRole == nil {
		return false // no childrem, so cycle
	}
	for _, containedRoleId := range roleBody.ContainedRole {
		if r.hasRoleCycle(containedRoleId, cycleFreeRoles, visitedRoles) {
			return true
		}
	}
	return false
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
	authorizations := []AuthorizationStruct{}
	// collect direct authorizations from role
	// ToDo: Merge authorizations!
	authorizations = append(authorizations, roleBody.Authorization...)

	// colllect indirect authorizations from embedded roles
	for _, embeddedRoleId := range roleBody.ContainedRole {
		indirectAuthorizations, err := r.getAuthorizationsFromRole(embeddedRoleId)
		if err != nil {
			return authorizations, err
		}
		// collect indirect authorizations from embedded role
		// ToDo: Merge authorizations!
		authorizations = append(authorizations, indirectAuthorizations...)
	}
	return authorizations, nil
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
