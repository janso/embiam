/*
The programm is a simple REST server and handles two request:
1. Verify identity of nick and password and receive identity token (POST /api/embiam/getToken)
2. Use identity token from 1. to securely call the API getTime (POST /api/gettime)

Test with CURL
1. Verify identity of nick and password and receive identity token (POST /api/embiam/getToken)

	$ curl -i -d '{"nick":"NICK0001","password":"SeCrEtSeCrEt"}' http://localhost:8242/api/embiam/getToken

	HTTP/1.1 200 OK
	...
	{"identityToken":"16dig-rand-token","validUntil":"YYYY-MM-DDThh:mm:ss.mmmmmmZ"}

2. use identity token when calling an api
	$ curl -i -H "Authorization: embiam 16dig-rand-token" http://localhost:8242/api/gettime

	HTTP/1.1 200 OK
	...
	current time :-)

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

// embiamCheckIdentityHandler checks the identity for nich and password and provides an identity token
// this is required for a call on an API, see gettimeHandler
func embiamCheckIdentityHandler(w http.ResponseWriter, r *http.Request) {
	// Log
	fmt.Printf("Request received from %s\t on %s\t %s\n", r.RemoteAddr, r.URL.Path, r.Method)

	// w.Header().Set("Access-Control-Allow-Origin", "*")
	// w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT")
	// w.Header().Set("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
	w.Header().Set("Content-Type", "application/json")

	// handle only POST method
	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	// extract client host from r.RemoteAddr
	clientHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// get credentials from boby of post request
	type credentialType struct {
		Nick     string `json:"nick"`
		Password string `json:"password"`
	}
	credentials := credentialType{}
	err = json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// check identity with nick and password
	// the generated identity token will be connected to clientHost to improve security
	identityToken, err := embiam.CheckIdentity(credentials.Nick, credentials.Password, clientHost)
	if err != nil {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	// no error, successfully identified

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
	if !embiam.IsAuthValueValid(authValue, clientHost) {
		http.Error(w, "", http.StatusForbidden)
		return
	}

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
	embiam.Initialize(new(embiam.DbMock))

	// starting server
	fmt.Printf("Starting Auth Server. Listening on port %s\n", embiam.Configuration.Port)
	http.HandleFunc("/api/embiam/getToken", embiamCheckIdentityHandler)
	http.HandleFunc("/api/gettime", gettimeHandler)
	log.Fatal(http.ListenAndServe(":"+embiam.Configuration.Port, nil))
}
