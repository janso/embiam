package main

import (
	"fmt"
	"log"

	"github.com/janso/embiam"
)

func main() {
	// set mock server for data
	// use e.g. the model for files for real implementations (EntityModelFile)
	model := embiam.EntityModelMock{}
	embiam.Initialize(model)

	// Use nick and password to get an identity token (for the client ip address)
	// this step is done, when the user was logged in.
	identityToken, err := embiam.GetIdentityToken("NICK4201", "SeCrEtSeCrEt", "localhost")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Identity was validated and an identity token was provided: %s\n\n", identityToken)

	// when an api is called, the identity token is passed from the client an can be checked

}
