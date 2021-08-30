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
	roleMap := embiam.RoleCacheMap{
		"embiam.admin": {
			Authorization: []embiam.AuthorizationStruct{{
				Ressource: "embiam.*",
				Action:    embiam.ActionMap{embiam.ActionAsteriks: {}},
			}},
			ContainedRole: []embiam.RoleIdType{},
		},
		"embiam.reader": {
			Authorization: []embiam.AuthorizationStruct{{
				Ressource: "embiam.*",
				Action:    embiam.ActionMap{"read": {}},
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
