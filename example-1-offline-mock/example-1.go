package main

import (
	"fmt"
	"log"

	"github.com/janso/embiam"
)

func main() {
	// Initiallize (with mock data)
	embiam.Initialize(new(embiam.EntityModelMock))
	// embiam.Initialize(embiam.EntityModelMock{}) is not working, because it returns type embiam.EntityModelMock.
	// new(embiam.EntityModelMock) returns *embiam.EntityModelMock.
	// see https://jordanorelli.com/post/32665860244/how-to-use-interfaces-in-go

	// Use nick and password to get an identity token (for the client's ip address)
	// this step is done, after the user has entered his credentials
	identityToken, err := embiam.CheckIdentity("NICK0001", "SeCrEtSeCrEt", "localhost")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Identity was validated and an identity token was provided: %s\n\n", identityToken)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token back to the server
	// The server checks the identity token quickly
	if embiam.IsIdentityTokenValid(identityToken.IdentityToken, "localhost") {
		fmt.Printf("Identity token is valid.")
	} else {
		log.Fatalln(err)
	}

	// now let's try to log on with wrong password
	for i := 0; i < 5; i++ {
		identityToken, err = embiam.CheckIdentity("NICK0001", "wrongPassword", "localhost")
		if err != nil {
			fmt.Printf("Error signin in: %s\n", err)
		} else {
			fmt.Printf("Identity was validated and an identity token was provided: %s\n\n", identityToken)
		}
	}
	// the entity was deactived... sign in with nick and password is not possible anymore.

}
