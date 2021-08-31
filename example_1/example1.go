package main

import (
	"fmt"
	"log"
	"time"

	"github.com/janso/embiam"
)

func main() {
	// Initiallize (with mock data)
	embiam.Initialize(new(embiam.DbTransient))

	// Generate test entities
	for i := 1; i < 4; i++ {
		nick := fmt.Sprintf("N1CK%04d", i)
		// create entity
		e := embiam.Entity{
			Nick:                 nick,
			PasswordHash:         embiam.Hash(`SeCrEtSeCrEt`),
			SecretHash:           embiam.Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
			Active:               true,
			WrongPasswordCounter: 0,
			LastSignInAttempt:    time.Time{},
			LastSignIn:           time.Now().UTC(),
			CreateTimeStamp:      time.Time{},
			UpdateTimeStamp:      time.Time{},
		}
		// save new entity
		err := embiam.Db.SaveEntity(&e)
		if err != nil {
			log.Fatal("error saving entity", err)
		}
	}

	// Use nick and password to get an identity token (for the client's ip address)
	// this step is done, after the user has entered his credentials
	fmt.Printf("Sign in with correct nick and password\n")
	identityToken, err := embiam.CheckIdentity(`N1CK0001`, `SeCrEtSeCrEt`, `localhost`)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("  Identity was validated and identity token %s was provided\n\n", identityToken.Token)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token back to the server
	// The server checks the identity token quickly
	fmt.Printf("Use identity token %s for e.g. a secure API call\n", identityToken.Token)
	if embiam.IsIdentityTokenValid(identityToken.Token, `localhost`) {
		fmt.Printf("  Identity token is valid\n\n")
	} else {
		log.Fatalln("invalid identity token")
	}

	// Try to validate an invalid token
	invalidIdentityToken := `ThisT0ken1sNotValid`
	fmt.Printf("Try with an INVALID identity token %s\n", invalidIdentityToken)
	if embiam.IsIdentityTokenValid(invalidIdentityToken, `localhost`) {
		log.Fatalf("check was positiv for an INVALID identity token %s; must be negativ\n", invalidIdentityToken)
	} else {
		fmt.Printf("  Identity token %s is invalid (as expected)\n\n", invalidIdentityToken)
	}

	// now let's try to log on with wrong password
	fmt.Printf("Sign in with INCORRECT nick and password\n")
	identityToken, err = embiam.CheckIdentity(`N1CK0001`, `wrongPassword`, `localhost`)
	if err != nil {
		fmt.Printf("  Error signin in: %s (as expected)\n\n", err)
	} else {
		log.Fatalln("must NOT return identityToken")
	}
}
