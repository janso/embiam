package embiam

import (
	"fmt"
	"log"
)

type (
	// RessourceType - a ressource is a thing that is relevant for authorization checks
	RessourceType string
	// ActivityType - an activity can be performed on a recource and is relevant for authority checks
	ActivityType string
	// ActivitySlice is a set of activities
	ActivitySlice []ActivityType
	// AuthorizationStruct describes a ressource together with actitivies
	AuthorizationStruct struct {
		Ressource RessourceType `json:"ressource"`
		Activity  ActivitySlice `json:"activity"`
	}
	// RoleIdType - a role is a collection of Authorization with an Id
	// it can also contain other roles and forms a hierarchical structure of authorizations
	RoleIdType string
	// RoleBodyStruct contains authorizations contained in the role and also other roles
	RoleBodyStruct struct {
		Authorization []AuthorizationStruct `json:"authorization"`
		ContainedRole []RoleIdType          `json:"containedRoles"`
	}
	// RoleMap combines the Id of the role with the role's body
	RoleMap map[RoleIdType]RoleBodyStruct

	// NickAuthorizationMap contains a Authorizations for nicks
	NickAuthorizationMap map[string][]AuthorizationStruct
)

/********************************************************************
	ROLE

	ToDo...
*********************************************************************/

// GetAuthorizationsForNick collects all authorizations from roles assigned to nick
func (r *RoleMap) GetAuthorizationsForEntity(entity *Entity) ([]AuthorizationStruct, error) {
	// collect authorizations from roles
	authorizations := []AuthorizationStruct{}
	for _, roleId := range entity.Roles {
		roleAuthorizations, err := r.GetAuthorizationsFromRole(roleId)
		if err != nil {
			return nil, err
		}
		// ToDo: Merge authorizations!
		authorizations = append(authorizations, roleAuthorizations...)
	}

	return authorizations, nil
}

// GetAuthorizationsFromRole get all authorizations from a role
// direct authorizations that are part of the role itself and indirect authorizations
// from embedded roles
// If roleId doesn't exist an error is returned
func (r RoleMap) GetAuthorizationsFromRole(roleId RoleIdType) ([]AuthorizationStruct, error) {
	roleBody, ok := r[roleId]
	if !ok {
		return nil, fmt.Errorf("Role %s doesn't exists\n", roleId)
	}
	authorizations := []AuthorizationStruct{}
	// collect direct authorizations from role
	// ToDo: Merge authorizations!
	authorizations = append(authorizations, roleBody.Authorization...)

	// colllect indirect authorizations from embedded roles
	for _, embeddedRoleId := range roleBody.ContainedRole {
		indirectAuthorizations, err := r.GetAuthorizationsFromRole(embeddedRoleId)
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
	AUTHORIZATIONS

	ToDo...
*********************************************************************/
var nickAuthorizations NickAuthorizationMap // authorizations of a nick
// ToDo: Add livetime managemnt - don't keep data of nick for ever

func BufferAuthorizationsForEntity(entity *Entity) error {
	authorizations, err := roles.GetAuthorizationsForEntity(entity)
	if err != nil {
		return err
	}
	nickAuthorizations[entity.Nick] = authorizations
	return nil
}

// IsAuthorized checks if the entity, provided through nick, is authorizied for action on ressource
func IsNickAuthorized(nick, ressource, action string) bool {
	// ToDo: implement
	return false
}

// list of all available roles
var roles RoleMap

func initializeAuthorizations() {
	// load roles
	roles, err := Db.ReadRoles()
	if err != nil {
		log.Fatalln(err)
	}
	if len(roles) == 0 {
		log.Printf("No roles loaded. Should have a minimum set of roles") // ToDo: remove
	}
}
