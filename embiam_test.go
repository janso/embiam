package embiam

import (
	"fmt"
	"testing"
	"time"
)

const testPassword = `PaSsWoRdPaSsWoRd`
const testHost = `127.0.0.1`

var testNickIdentityToken map[string]identityTokenStruct

func signIn(t *testing.T, nick, password string) {
	// use credentials to get identity token
	identityToken, err := CheckIdentity(nick, testPassword, testHost)
	if err != nil {
		t.Errorf("in signIn() function CheckIdentity(nick, TestPassword, host) returned error %s ; want identity token", err)
	}
	// save nick with identity token
	testNickIdentityToken[nick] = identityToken
}

func TestGetIdentityTokenMock(t *testing.T) {
	const nickCount = 5
	const nickPattern = "nick%04d"
	const testNick = "nick0001"

	// initialize embiam
	Initialize(new(DbTransient))

	// Generate test entities
	for i := 1; i <= nickCount; i++ {
		nick := fmt.Sprintf(nickPattern, i)
		e := Entity{
			Nick:                 nick,
			PasswordHash:         Hash(testPassword),
			SecretHash:           Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
			Active:               true,
			WrongPasswordCounter: 0,
			LastSignInAttempt:    time.Time{},
			LastSignIn:           time.Now().UTC(),
			CreateTimeStamp:      time.Time{},
			UpdateTimeStamp:      time.Time{},
		}
		// save new entity
		err := Db.SaveEntity(&e)
		if err != nil {
			t.Errorf("Db.SaveEntity(&e) returned error %s; want save entity without error", err)
		}
	}

	// Use credentials (nick and password) to get an identity token (for the client's ip address)
	// Sign in with correct credentials
	identityToken, err := CheckIdentity(testNick, testPassword, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(testNick, TestPassword, host) returned error %s ; want identity token", err)
	}

	// validate if identity token is valid
	if !IsIdentityTokenValid(identityToken.Token, testHost) {
		t.Errorf("IsIdentityTokenValid(identityToken.Token, host) has returned false; want true")
	}

	// Use wrong credentials to get an identity token
	identityToken, err = CheckIdentity(testNick, `invalidPassword`, testHost)
	if err == nil {
		t.Errorf("CheckIdentity(testNick, `invalidPassword`, host) hasn't returned and error; want and error message")
	}

	// initialize map of nicks with identity tokens
	testNickIdentityToken = make(map[string]identityTokenStruct)

	// sign in for NICK0001, NICK0002, ... and save identity tokens in NickIdentityToken (type map[string]identityTokenStruct)
	for i := 1; i <= nickCount; i++ {
		nick := fmt.Sprintf(nickPattern, i)
		go signIn(t, nick, testPassword)
	}
	time.Sleep(time.Second) // ToDo: synchronize with channels

	// check if NickIdentityToken contains all identity tokens
	for i := 1; i <= nickCount; i++ {
		nick := fmt.Sprintf(nickPattern, i)
		identityToken, exists := testNickIdentityToken[nick]
		if !exists {
			t.Errorf("identity token for nick %s doesn't exist after concurrent sign in; want identity token", nick)
		}
		if !IsIdentityTokenValid(identityToken.Token, testHost) {
			t.Errorf("IsIdentityTokenValid(identityToken.Token, host) has returned false after concurrent sign in; want true")
		}
	}
}

func TestCreateEntityWithFileDb(t *testing.T) {
	const nickCount = 5
	const nickPattern = "nick%04d"

	// Initiallize (using filesystem as database)
	model := new(DbFile)
	Initialize(model)

	// clean up db
	t.Log("Deleting files from " + model.EntityFilePath)
	model.DeleteFilesFromDirectory(model.EntityFilePath)
	t.Log("Deleting files from " + model.EntityTokenFilePath)
	model.DeleteFilesFromDirectory(model.EntityTokenFilePath)

	// Generate test entities
	for i := 1; i <= nickCount; i++ {
		nick := fmt.Sprintf(nickPattern, i)
		e := Entity{
			Nick:                 nick,
			PasswordHash:         Hash(testPassword),
			SecretHash:           Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
			Active:               true,
			WrongPasswordCounter: 0,
			LastSignInAttempt:    time.Time{},
			LastSignIn:           time.Now().UTC(),
			CreateTimeStamp:      time.Time{},
			UpdateTimeStamp:      time.Time{},
		}
		// save new entity
		err := Db.SaveEntity(&e)
		if err != nil {
			t.Errorf("Db.SaveEntity(&e) returned error %s; want save entity without error", err)
		}
	}

	/*
	   GENERATE SOME ENTITIES (users)
	   following the usual process:
	   1. the admin generates an entity token and provides it to the user
	   2. the user creates his personal entity using the entity token
	*/
	// 1. generate entity tokens (they are provided by the adminitrator and used by the user to generate the entity)
	entityTokens := make([]string, 0, nickCount)
	for i := 0; i < 3; i++ {
		entityToken := NewEntityToken()
		entityToken.Save()
		entityTokens = append(entityTokens, entityToken.Token)
	}

	// 2. use entity tokens to generate real, usable entities
	entity := Entity{}
	password := ""
	var err error
	for i := 0; i < 3; i++ {
		entity, password, _, err = NewEntity(entityTokens[i])
		if err != nil {
			t.Errorf("NewEntity(entityTokens[i]) returned error %s; want new entity without error", err)
		}
	}

	/*
		GET IDENTITY TOKEN
		from nick and password
	*/
	// provide nick and password and get identity token back
	identityToken, err := CheckIdentity(entity.Nick, password, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(entity.Nick, password, testHost) returned error %s; want identity token without error", err)
	}
	// receive an identity token to use later (without credentials)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token  to the server.
	// The server checks the identity token
	if !IsIdentityTokenValid(identityToken.Token, testHost) {
		t.Errorf("IsIdentityTokenValid(identityToken.Token, testHost) returned false (invalid identity); want true (identity token need to be valid)")
	}

}
