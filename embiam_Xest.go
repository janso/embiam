package embiam

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

const TEST_PASSWORD = `PaSsWoRdPaSsWoRd`
const TEST_HOST = `127.0.0.1`
const NICK_PATTERN = "N1CK%04d"

var testNickIdentityToken map[string]identityTokenStruct

func signIn(t *testing.T, nick, password string) {
	// use credentials to get identity token
	identityToken, err := CheckIdentity(nick, TEST_PASSWORD, TEST_HOST)
	if err != nil {
		t.Errorf("in signIn() function CheckIdentity(nick, TestPassword, host) returned error %s ; want identity token", err)
	}
	// save nick with identity token
	testNickIdentityToken[nick] = identityToken
}

func TestGetIdentityTokenMock(t *testing.T) {
	const NICK_COUNT = 5
	const TEST_NICK = "N1CK0001"

	// initialize embiam
	Initialize(new(DbTransient))

	// Generate test entities
	for i := 1; i <= NICK_COUNT; i++ {
		nick := fmt.Sprintf(NICK_PATTERN, i)
		e := Entity{
			Nick:                 nick,
			PasswordHash:         Hash(TEST_PASSWORD),
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
	identityToken, err := CheckIdentity(TEST_NICK, TEST_PASSWORD, TEST_HOST)
	if err != nil {
		t.Errorf("CheckIdentity(testNick, TestPassword, host) returned error %s ; want identity token", err)
	}

	// validate if identity token is valid
	if !IsIdentityTokenValid(identityToken.Token, TEST_HOST) {
		t.Errorf("IsIdentityTokenValid(identityToken.Token, host) has returned false; want true")
	}

	// Use wrong credentials to get an identity token
	identityToken, err = CheckIdentity(TEST_NICK, `invalidPassword`, TEST_HOST)
	if err == nil {
		t.Errorf("CheckIdentity(testNick, `invalidPassword`, host) hasn't returned and error; want and error message")
	}

	// initialize map of nicks with identity tokens
	testNickIdentityToken = make(map[string]identityTokenStruct)

	// sign in for NICK0001, NICK0002, ... and save identity tokens in NickIdentityToken (type map[string]identityTokenStruct)
	for i := 1; i <= NICK_COUNT; i++ {
		nick := fmt.Sprintf(NICK_PATTERN, i)
		signIn(t, nick, TEST_PASSWORD)
	}

	// check if NickIdentityToken contains all identity tokens
	for i := 1; i <= NICK_COUNT; i++ {
		nick := fmt.Sprintf(NICK_PATTERN, i)
		identityToken, exists := testNickIdentityToken[nick]
		if !exists {
			t.Errorf("identity token for nick %s doesn't exist after concurrent sign in; want identity token", nick)
		}
		if !IsIdentityTokenValid(identityToken.Token, TEST_HOST) {
			t.Errorf("IsIdentityTokenValid(identityToken.Token, host) has returned false for %s after concurrent sign in; want true", nick)
		}
	}
}

func TestCreateEntityWithFileDb(t *testing.T) {
	const NICK_COUNT = 5

	// Initiallize (using filesystem as database)
	model := new(DbFile)
	Initialize(model)

	// clean up db
	model.DeleteContentsFromDirectory(model.EntityFilePath)
	model.DeleteContentsFromDirectory(model.EntityTokenFilePath)

	// Generate test entities
	for i := 1; i <= NICK_COUNT; i++ {
		nick := fmt.Sprintf(NICK_PATTERN, i)
		e := Entity{
			Nick:                 nick,
			PasswordHash:         Hash(TEST_PASSWORD),
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
	entityTokens := make([]string, 0, NICK_COUNT)
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
		with nick and password
	*/
	// provide nick and password and get identity token back
	identityToken, err := CheckIdentity(entity.Nick, password, TEST_HOST)
	if err != nil {
		t.Errorf("CheckIdentity(entity.Nick, password, testHost) returned error %s; want identity token without error", err)
	}
	// receive an identity token to use later (without credentials)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token to the server and the server checks the identity token
	for i := 0; i <= 5; i++ {
		if !IsIdentityTokenValid(identityToken.Token, TEST_HOST) {
			t.Errorf("IsIdentityTokenValid(identityToken.Token, testHost) returned false (invalid identity); want true (identity token need to be valid)")
		}
	}

	/*
		GET IDENTITY TOKEN for AUTHVALUE
		The client send an authorization value in the header of the http request
		Authorization:embiam based64-encoded-string from nick:password, e.g. "Authorization:embiam TEFDVlVLQko6RHJIWGhNdjd1QisuQ3hjNg=="
		this value contains the (no crypted) credetials and can be used directly.
	*/
	// simulate authValue
	authValue := "embiam " + base64.StdEncoding.EncodeToString([]byte(entity.Nick+":"+password))
	// get identityToken with authValue
	identityToken, err = CheckAuthIdentity(authValue, TEST_HOST)
	if err != nil {
		t.Errorf("CheckAuthIdentity(authValue, testHost) with authValue %s returned error %s; want identity token without error", authValue, err)
	}

	// check identityToken from Authorizantion header
	// Authorization:embiam based64-encoded-string from identityToken, e.g. "Authorization:embiam TEFDVlVLQko6RHJIWGhNdjd1QisuQ3hjNg=="
	authValue = "embiam " + base64.StdEncoding.EncodeToString([]byte(identityToken.Token))
	for i := 0; i <= 5; i++ {
		if !IsAuthIdentityTokenValid(authValue, TEST_HOST) {
			t.Errorf("IsAuthIdentityTokenValid(authValue, testHost) returned false (invalid identity); want true (identity token need to be valid)")
		}
	}

	/*
		SIGN IN WITH WRONG CREDETIALS
		After a sign in with wrong credentials the number of false attempts is increased. Also the time of the wrong attempt is logged.
	*/
	_, err = CheckIdentity(entity.Nick, `Wr0ngPassWord`, TEST_HOST)
	if err == nil {
		t.Errorf("CheckIdentity(entity.Nick, `Wr0ngPassWord`, testHost) returned NO error; want error")
	}
	e, err := Db.ReadEntityByNick(entity.Nick)
	if err != nil {
		t.Errorf("Db.ReadEntityByNick(entity.Nick) for %s returned error %s; want entity without error", entity.Nick, err)
	}
	if e.WrongPasswordCounter != 1 {
		t.Errorf("e.WrongPasswordCounter = %d; want 1", e.WrongPasswordCounter)
	}

	/*
		LOG ENTITY
		After serveral wrong sign in attempts the entity is locked.
		The number of attempts can be configured, check embiam.Configuration.MaxSignInAttempts
		The entity is locked by setting Entity.Active to false.
	*/
	for i := 0; i <= Configuration.MaxSignInAttempts; i++ {
		_, err = CheckIdentity(entity.Nick, `Wr0ngPassWord`, TEST_HOST)
		if err == nil {
			t.Errorf("CheckIdentity(entity.Nick, `Wr0ngPassWord`, testHost) returned NO error; want error")
		}
	}
	e, err = Db.ReadEntityByNick(entity.Nick)
	if err != nil {
		t.Errorf("Db.ReadEntityByNick(entity.Nick) for %s returned error %s; want entity without error", entity.Nick, err)
	}
	if e.Active {
		t.Errorf("e.Active = true; want false")
	}
	if e.WrongPasswordCounter != Configuration.MaxSignInAttempts+1 {
		t.Errorf("e.WrongPasswordCounter = %d; want %d", e.WrongPasswordCounter, Configuration.MaxSignInAttempts+1)
	}
}
