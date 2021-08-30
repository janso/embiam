package main

import (
	"fmt"
	"log"

	"github.com/janso/embiam"
)

func main() {
	db := new(embiam.DbFile)
	embiam.Initialize(db)

	// create example roleMap
	roleMap := embiam.RoleMap{
		"embiam.admin": {
			Authorization: []embiam.AuthorizationStruct{{
				Ressource: "embiam.*",
				Activity:  []embiam.ActivityType{"*"},
			}},
			ContainedRole: []embiam.RoleIdType{},
		},
		"embiam.reader": {
			Authorization: []embiam.AuthorizationStruct{{
				Ressource: "embiam.*",
				Activity:  []embiam.ActivityType{"read"},
			}},
			ContainedRole: []embiam.RoleIdType{},
		},
	}

	// save them
	err := db.SaveRoles(roleMap)
	if err != nil {
		log.Fatalln(err)
	}

	// load them again
	readRoleMap, err := db.ReadRoles()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(readRoleMap)
}
