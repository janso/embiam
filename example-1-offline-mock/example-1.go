package main

import (
	"fmt"
	"log"

	"github.com/janso/embiam"
)

func main() {
	// Initiallize (with mock data)
	embiam.Initialize(embiam.EntityModelMock{})

	// Use nick and password to get an identity token (for the client's ip address)
	// this step is done, after the user has entered his credentials
	identityToken, err := embiam.GetIdentityToken("NICK4201", "SeCrEtSeCrEt", "localhost")
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
}
