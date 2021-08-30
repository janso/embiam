package embiam

import (
	"fmt"
	"testing"
)

func TestAuth(t *testing.T) {
	db := new(DbFile)
	Initialize(db)

	// create example roleMap
	roleMap := RoleMap{
		"embiam.admin": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "embiam.*",
					Activity:  []ActivityType{"read"},
				},
			},
		},
		"embiam.reader": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "embiam.*",
					Activity:  []ActivityType{"read"},
				},
			},
		},
	}

	err := db.SaveRoles(roleMap)
	if err != nil {
		t.Errorf("db.SaveRoles(&roles) returned error %s; want no error\n", err)
	}

	readRoles, err := db.ReadRoles()
	if err != nil {
		t.Errorf("db.ReadRoles(&roles) returned error %s; want no error\n", err)
	}
	fmt.Printf("%s\n", readRoles)
}
