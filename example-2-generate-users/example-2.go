package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/janso/embiam"
)

func main() {
	// Initiallize (using filesystem as database)
	embiam.Initialize(new(embiam.DbFile))

	// clean up db
	removeContents(embiam.Configuration.DBPath + embiam.EntityFilePath)
	removeContents(embiam.Configuration.DBPath + embiam.EntityTokenFilePath)

	/*
	   GENERATE SOME ENTITIES (users)
	   following the usual process:
	   1. the admin generates an entity token and provides it to the user
	   2. the user creates his personal entity using the entity token
	*/
	// 1. generate entity tokens (they are provided by the adminitrator and used by the user to generate the entity)
	entityTokenCount := 3
	entityTokens := make([]string, 0, entityTokenCount)
	for i := 0; i < 3; i++ {
		entityToken := embiam.NewEntityToken()
		entityToken.Save()
		entityTokens = append(entityTokens, entityToken.Token)
	}

	// 2. use entity tokens to generate real, usable entities
	entity := embiam.Entity{}
	password := ""
	secret := ""
	var err error
	for i := 0; i < 3; i++ {
		entity, password, secret, err = embiam.NewEntity(entityTokens[i])
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("New entity created successfully\n  Nick      %s\n", entity.Nick)
		fmt.Printf("  Password  %s\n  Hash      %s\n", password, entity.PasswordHash)
		fmt.Printf("  Secret    %s\n  Hash      %s\n\n", secret, entity.SecretHash)
	}

	/*
		GET IDENTITY TOKEN
		from nick and password
	*/
	// provide nick and password and get identity token back
	identityToken, err := embiam.CheckIdentity(entity.Nick, password, "localhost")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Identity of %s was validated. The identity token %s was provided\n\n", entity.Nick, identityToken.Token)
	// receive an identity token to use later (without credentials)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token  to the server.
	// The server checks the identity token
	if embiam.IsIdentityTokenValid(identityToken.Token, "localhost") {
		fmt.Printf("Identity token is valid.")
	} else {
		log.Fatalln(err)
	}
}

func removeContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}