/*
The programm is a simple REST server and handles two request:
1. Verify identity of nick and password and receive identity token (POST /api/embiam/getToken)
2. Use identity token from 1. to securely call the API getTime (POST /api/gettime)

Test with CURL
1. Verify identity of nick and password and receive identity token (POST /api/embiam/getToken)
	This example runs with a mock entity that has the nick NICK0001. It uses the password SeCrEtSeCrEt.
	Nick and password are concatenated to NICK0001:SeCrEtSeCrEt Both terms are separated by a colon.
	The result is base64-encoded, and leads to the credentials TklDSzAwMDE6U2VDckV0U2VDckV0.

	make a HTTP GET request to http://localhost:8242/api/embiam/identityToken and
	use the head field "Authorization:embiam TjFDSzAwMDE6U2VDckV0U2VDckV0"

	$ curl -i -H "Authorization:embiam TjFDSzAwMDE6U2VDckV0U2VDckV0" http://localhost:8242/api/embiam/identityToken

	you receive
	HTTP/1.1 200 OK
	...
	{"identityToken":"the-acutal-identity-token","validUntil":"YYYY-MM-DDThh:mm:ss.mmmmmmZ"}

2. use identity token the-acutal-identity-token when calling an API, api/gettime in this example
	$ curl -i -H "Authorization: embiam the-acutal-identity-token" http://localhost:8242/api/gettime

	HTTP/1.1 200 OK
	...
	server time

*/
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/janso/embiam"
)

// embiamidentityTokenGetHandler checks the identity for nick and password and provides an identity token
// this is required for a call on an API, see gettimeHandler
func embiamidentityTokenGetHandler(w http.ResponseWriter, r *http.Request) {
	// Log
	fmt.Printf("Request received from %s\t on %s\t %s\n", r.RemoteAddr, r.URL.Path, r.Method)

	// w.Header().Set("Access-Control-Allow-Origin", "*")
	// w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT")
	// w.Header().Set("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
	w.Header().Set("Content-Type", "application/json")

	// handle only GET method
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	// extract client host from r.RemoteAddr
	validFor, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// get credentails from header
	authValue := r.Header.Get("Authorization")

	// check identity with authValue. It contaim the prefix 'embiam' a space and nick and password
	// nick and password are concatenant with a colon seperating both. The result is base64 encoded
	// like in simple authentication. e.g. 'embiam REhXUEhTVUw6ZFRjaHguNy15aC5CREVjNw=='
	// the generated identity token will be connected to validFor to improve security
	identityToken, nick, err := embiam.CheckAuthIdentity(authValue, validFor)
	if err != nil {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	// no error, successfully identified
	fmt.Printf("\tIdentity %s verfied and identity token %s provided\n", nick, identityToken.Token)

	// send identity token back
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(identityToken)
}

// gettimeHandler is the handler for an API that provides the current time
// - but only if you are authorized and have a valid identity token
func gettimeHandler(w http.ResponseWriter, r *http.Request) {
	// Log
	fmt.Printf("Request received from %s\t on %s\t %s\n", r.RemoteAddr, r.URL.Path, r.Method)

	// extract client host from r.RemoteAddr
	clientHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// get identity token from header
	authValue := r.Header.Get("Authorization")
	if !embiam.IsAuthIdentityTokenValid(authValue, clientHost) {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	fmt.Printf("\tAuthorization check successful. Identity token is valid.\n\n")

	// w.Header().Set("Access-Control-Allow-Origin", "*")
	// w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT")
	// w.Header().Set("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
	w.Header().Set("Content-Type", "application/json")

	// check HTTP method
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	// send response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", time.Now().UTC())
}

func main() {
	// Initiallize (with database in filesystem)
	embiam.Initialize(new(embiam.DbTransient))
	// create entity
	e := embiam.Entity{
		Nick:                 `N1CK0001`,
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

	// starting server
	fmt.Printf("Starting Auth Server. Listening on port %s\n", embiam.Configuration.Port)
	http.HandleFunc("/api/embiam/identityToken", embiamidentityTokenGetHandler)
	http.HandleFunc("/api/gettime", gettimeHandler)
	log.Fatal(http.ListenAndServe(":"+embiam.Configuration.Port, nil))
}
