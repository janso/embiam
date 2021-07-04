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
	embiam.Initialize(new(embiam.EntityModelFileDB))

	// generate some entities (users) folder ./db/nick/
	removeContents(embiam.Configuration.DBPath + `nick/`)
	entity := embiam.Entity{}
	password := ""
	secret := ""
	for i := 0; i < 3; i++ {
		entity = embiam.NewEntity()
		password = embiam.GeneratePassword(16)
		secret = embiam.GeneratePassword(32)
		entity.PasswordHash = embiam.Hash(password)
		entity.SecretHash = embiam.Hash(secret)
		err := entity.Save() // we save hash values for password and secret - the originals stay only with the owner
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("New entity created successfully\n  Nick      %s\n", entity.Nick)
		fmt.Printf("  Password  %s\n  Hash      %s\n", password, entity.PasswordHash)
		fmt.Printf("  Secret    %s\n  Hash      %s\n\n", secret, entity.SecretHash)
	}

	// Use nick and password to authentify
	identityToken, err := embiam.CheckIdentity(entity.Nick, password, "localhost")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Identity of %s was validated. The identity token %s was provided\n\n", entity.Nick, identityToken)
	// receive an identity token to use later (without credentials)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token  to the server.
	// The server checks the identity token
	if embiam.IsIdentityTokenValid(identityToken.IdentityToken, "localhost") {
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
