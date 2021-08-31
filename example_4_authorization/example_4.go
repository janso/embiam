package main

import (
	"fmt"
	"log"
	"time"

	"github.com/janso/embiam"
)

func main() {
	const (
		testPassword = `PaSsWoRdPaSsWoRd`
		nickPattern  = "N1CK%04d"
	)

	db := new(embiam.DbFile)
	embiam.Initialize(db)

	// create example roleMap
	roleExample := embiam.RoleCacheMap{
		"embiam.admin": {
			Authorization: []embiam.AuthorizationStruct{
				{
					Ressource: "embiam.*",
					Action:    embiam.ActionMap{embiam.ActionAsteriks: {}},
				},
			},
		},
		"embiam.reader": {
			Authorization: []embiam.AuthorizationStruct{
				{
					Ressource: "embiam.*",
					Action:    embiam.ActionMap{"read": {}},
				},
			},
		},
	}

	// save roles
	err := db.SaveRoles(roleExample)
	if err != nil {
		log.Printf("db.SaveRoles(&roles) returned error %s; want no error\n", err)
	}

	// load them (to roleCache)
	err = embiam.ReadRoles()
	if err != nil {
		log.Printf("embiam.ReadRoles() returned error %s; want no error\n", err)
	}

	// generate example entity with role embiam.reader
	entity1 := embiam.Entity{
		Nick:                 fmt.Sprintf(nickPattern, 1),
		PasswordHash:         embiam.Hash(testPassword),
		SecretHash:           embiam.Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
		Active:               true,
		WrongPasswordCounter: 0,
		LastSignInAttempt:    time.Time{},
		LastSignIn:           time.Now().UTC(),
		CreateTimeStamp:      time.Time{},
		UpdateTimeStamp:      time.Time{},
		Roles:                []embiam.RoleIdType{"embiam.reader"},
	}
	err = db.SaveEntity(&entity1)
	if err != nil {
		log.Printf("Db.SaveEntity(&entity1) returned error %s; want save entity without error\n", err)
	}

	// Sign in with correct credentials
	identityToken1, err := embiam.CheckIdentity(entity1.Nick, testPassword, "localhost")
	if err != nil {
		log.Printf("CheckIdentity(testNick, testPassword, testHost) returned error %s ; want identity token\n", err)
		return
	}
	fmt.Printf("identity Token provided (and authorizations of nick aggregated and buffered)")
	// check authorization for entity 1
	if !embiam.IsAuthorized(identityToken1.Token, "embiam.entity", "read") {
		log.Printf("IsAuthorized(identityToken1.Token, embiam.entity, read) returned false; want true\n")
	}
	if embiam.IsAuthorized(identityToken1.Token, "embiam.entity", "write") {
		log.Printf("IsAuthorized(identityToken1.Token, embiam.entity, write) returned true; want false\n")
	}
	if embiam.IsAuthorized(identityToken1.Token, "embiam.entity", "*") {
		log.Printf("IsAuthorized(identityToken1.Token, embiam.entity, *b) returned true; want false\n")
	}
	if !embiam.IsAuthorized(identityToken1.Token, "embiam.marmelquark", "read") {
		log.Printf("IsAuthorized(identityToken1.Token, embiam.marmelquark, read) returned false; want true\n")
	}

}
