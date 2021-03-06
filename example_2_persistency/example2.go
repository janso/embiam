package main

import (
	"fmt"
	"log"

	"github.com/janso/embiam"
)

func main() {
	// Initiallize (using filesystem as database)
	embiamDb := new(embiam.DbFile)
	embiam.Initialize(embiamDb)

	// clean up db
	embiamDb.DeleteContentsFromDirectory(embiamDb.EntityFilePath)
	embiam.InitializeDirectory(embiamDb.EntityDeletedFilePath) // recreate directory
	embiamDb.DeleteContentsFromDirectory(embiamDb.EntityTokenFilePath)

	/*
	   GENERATE SOME ENTITIES (users)
	   following the usual process:
	   1. the admin generates an entity token and provides it to the user
	   2. the user creates his personal entity using the entity token
	*/
	// 1. generate entity tokens (they are provided by the adminitrator and used by the user to generate the entity)
	entityTokenCount := 3
	entityTokens := make([]embiam.EntityToken, 0, entityTokenCount)
	for i := 0; i < 3; i++ {
		entityToken, err := embiam.NewEntityToken()
		if err != nil {
			log.Fatalln(err)
		}
		entityTokens = append(entityTokens, entityToken)
	}

	// 2. use entity tokens to generate real, usable entities
	newEntity := embiam.NewEntityStruct{}
	var err error
	for i := 0; i < 3; i++ {
		newEntity, err = embiam.NewEntity(entityTokens[i].Token, entityTokens[i].Pin)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("New entity created successfully\n  Nick      %s\n", newEntity.Nick)
		fmt.Printf("  Password  %s\n  Hash      %s\n", newEntity.Password, newEntity.PasswordHash)
		fmt.Printf("  Secret    %s\n  Hash      %s\n\n", newEntity.Secret, newEntity.SecretHash)
	}

	/*
		GET IDENTITY TOKEN
		from nick and password
	*/
	// provide nick and password and get identity token back
	identityToken, err := embiam.CheckIdentity(newEntity.Nick, newEntity.Password, "localhost")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Identity of %s was validated. The identity token %s was provided\n\n", newEntity.Nick, identityToken.Token)
	// receive an identity token to use later (without credentials)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token  to the server.
	// The server checks the identity token
	if embiam.IsIdentityTokenValid(identityToken.Token, "localhost") {
		fmt.Printf("Identity token is valid.\n\n")
	} else {
		log.Fatalln(err)
	}

	/*
		READ ENTITIES
	*/
	entity, err := embiam.Db.ReadEntityByNick(newEntity.Nick)
	if err != nil {
		log.Fatalln(err)
	}
	publicEntity, err := embiam.Db.ReadPublicEntityByNick(newEntity.Nick)
	if err != nil {
		log.Fatalln(err)
	}
	if entity.Nick != publicEntity.Nick {
		log.Fatalln(err)
	}
	if entity.CreateTimeStamp != publicEntity.CreateTimeStamp {
		log.Fatalln(err)
	}
	fmt.Printf("Entity %s successfully read\n\n", newEntity.Nick)

	/*
		DELETE ENTITY
		The entities are moved to folder deleted in the folder of entities
	*/
	err = embiam.Db.DeleteEntity(newEntity.Nick)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Entity %s successfully deleted\n\n", newEntity.Nick)
}
