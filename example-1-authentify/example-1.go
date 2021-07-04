package main

import (
	"fmt"
	"log"
	"time"

	"github.com/janso/embiam"
)

func main() {
	// Initiallize (with mock data)
	embiam.Initialize(new(embiam.DbMock))
	// embiam.Initialize(embiam.EntityModelMock{}) is not working, because it returns type embiam.EntityModelMock.
	// new(embiam.EntityModelMock) returns *embiam.EntityModelMock.
	// see https://jordanorelli.com/post/32665860244/how-to-use-interfaces-in-go

	// Generate test entities
	GenerateEntities()

	// Use nick and password to get an identity token (for the client's ip address)
	// this step is done, after the user has entered his credentials
	fmt.Printf("Sign in with correct nick and password\n")
	identityToken, err := embiam.CheckIdentity("NICK0001", "SeCrEtSeCrEt", "localhost")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("  Identity was validated and identity token %s was provided\n\n", identityToken.Token)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token back to the server
	// The server checks the identity token quickly
	fmt.Printf("Use identity token %s for e.g. a secure API call\n", identityToken.Token)
	if embiam.IsIdentityTokenValid(identityToken.Token, "localhost") {
		fmt.Printf("  Identity token is valid\n\n\n")
	} else {
		log.Fatalln(err)
	}

	// now let's try to log on with wrong password
	fmt.Printf("Sign in with INCORRECT nick and password\n")
	identityToken, err = embiam.CheckIdentity("NICK0001", "wrongPassword", "localhost")
	if err != nil {
		fmt.Printf("  Error signin in: %s\n", err)
	} else {
		log.Fatalln("must not return identityToken")
	}

}

// Generate test entities
func GenerateEntities() error {
	for i := 1; i < 4; i++ {
		e := embiam.Entity{
			Nick:                 fmt.Sprintf("NICK%04d", i),
			PasswordHash:         embiam.Hash("SeCrEtSeCrEt"),
			SecretHash:           "",
			Active:               true,
			LastSignIn:           time.Time{},
			WrongPasswordCounter: 0,
			CreateTimeStamp:      time.Now().UTC(),
			UpdateTimeStamp:      time.Time{},
		}
		err := embiam.Db.SaveEntity(&e)
		if err != nil {
			return err
		}
	}
	return nil
}
