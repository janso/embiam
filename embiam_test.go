package embiam

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

const (
	testPassword = `PaSsWoRdPaSsWoRd`
	testHost     = `127.0.0.1`
	nickPattern  = "N1CK%04d"
)

var testNickIdentityToken map[string]identityTokenStruct

func signIn(t *testing.T, nick, password string) {
	// use credentials to get identity token
	identityToken, err := CheckIdentity(nick, testPassword, testHost)
	if err != nil {
		t.Errorf("in signIn() function CheckIdentity(nick, TestPassword, host) returned error %s ; want identity token\n", err)
	}
	// save nick with identity token
	testNickIdentityToken[nick] = identityToken
}

func TestGetIdentityTokenMock(t *testing.T) {
	const (
		nickCount = 5
		testNick  = `N1CK0001`
	)
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
			t.Errorf("Db.SaveEntity(&e) returned error %s; want save entity without error\n", err)
		}
	}

	// Use credentials (nick and password) to get an identity token (for the client's ip address)
	// Sign in with correct credentials
	identityToken, err := CheckIdentity(testNick, testPassword, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(testNick, TestPassword, host) returned error %s ; want identity token\n", err)
	}

	// validate if identity token is valid
	if !IsIdentityTokenValid(identityToken.Token, testHost) {
		t.Errorf("IsIdentityTokenValid(identityToken.Token, host) has returned false; want true\n")
	}

	// Use wrong credentials to get an identity token
	identityToken, err = CheckIdentity(testNick, `invalidPassword`, testHost)
	if err == nil {
		t.Errorf("CheckIdentity(testNick, `invalidPassword`, host) hasn't returned and error; want and error message\n")
	}

	// initialize map of nicks with identity tokens
	testNickIdentityToken = make(map[string]identityTokenStruct)

	// sign in for NICK0001, NICK0002, ... and save identity tokens in NickIdentityToken (type map[string]identityTokenStruct)
	for i := 1; i <= nickCount; i++ {
		nick := fmt.Sprintf(nickPattern, i)
		signIn(t, nick, testPassword)
	}

	// check if NickIdentityToken contains all identity tokens
	for i := 1; i <= nickCount; i++ {
		nick := fmt.Sprintf(nickPattern, i)
		identityToken, exists := testNickIdentityToken[nick]
		if !exists {
			t.Errorf("identity token for nick %s doesn't exist after concurrent sign in; want identity token\n", nick)
		}
		if !IsIdentityTokenValid(identityToken.Token, testHost) {
			t.Errorf("IsIdentityTokenValid(identityToken.Token, host) has returned false for %s after concurrent sign in; want true\n", nick)
		}
	}
}

func TestCreateEntityWithFileDb(t *testing.T) {
	const nickCount = 4
	const entityCount = 4

	// Initiallize (using filesystem as database)
	db := new(DbFile)
	Initialize(db)

	// clean up db
	db.DeleteContentsFromDirectory(db.EntityFilePath)
	InitializeDirectory(db.EntityDeletedFilePath) // recreate directory
	db.DeleteContentsFromDirectory(db.EntityTokenFilePath)

	// Generate test entities
	// Create them directly without the usualprocedure with entity tokens
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
			t.Errorf("Db.SaveEntity(&e) returned error %s; want save entity without error\n", err)
		}
	}

	/*
	   GENERATE SOME ENTITIES (users)
	   following the usual process:
	   1. the admin generates an entity token and provides it to the user
	   2. the user creates his personal entity using the entity token
	*/
	// 1. generate entity tokens (they are provided by the adminitrator and used by the user to generate the entity)
	entityTokens := make([]EntityToken, 0, nickCount)
	for i := 0; i < entityCount; i++ {
		entityToken, err := NewEntityToken()
		if err != nil {
			t.Errorf("NewEntityToken(...) returned error %s; want new entity token without error\n", err)
		}
		entityTokens = append(entityTokens, entityToken)
	}

	// 2. use entity tokens to generate real, usable entities
	newEntity := NewEntityStruct{}
	var err error
	for i := 0; i < entityCount; i++ {
		newEntity, err = NewEntity(entityTokens[i].Token, entityTokens[i].Pin)
		if err != nil {
			t.Errorf("NewEntity(...) returned error %s; want new entity without error\n", err)
		}
	}

	// 3. generate a disturbing file (that is not a nick)
	wrongEntity := Entity{
		Nick:                 ".DS_Store",
		PasswordHash:         "",
		SecretHash:           "",
		Active:               false,
		WrongPasswordCounter: 0,
		LastSignInAttempt:    time.Time{},
		LastSignIn:           time.Time{},
		CreateTimeStamp:      time.Now().UTC(),
		UpdateTimeStamp:      time.Time{},
	}
	err = Db.SaveEntity(&wrongEntity)
	if err != nil {
		t.Errorf("Db.SaveEntity(&wrongEntity) returned error %s; want new entity without error\n", err)
	}

	/*
		READ ENTITIES
	*/
	// 1. get list of all entities
	nicklist, err := db.ReadEntityList()
	if err != nil {
		t.Errorf("model.ReadEntityList() returned error %s; want list of nicks\n", err)
	}

	// 2. read each individual entity using the list
	entityList := make([]Entity, 0, len(nicklist))
	publicEntityList := make([]PublicEntity, 0, len(nicklist))
	for _, nick := range nicklist {
		entity, err := db.ReadEntityByNick(nick)
		if err != nil {
			t.Errorf("model.ReadEntityByNick(nick) returned error %s for nick %s; want entity for nick\n", err, nick)
		}
		publicEntity, err := db.ReadPublicEntityByNick(nick)
		if err != nil {
			t.Errorf("model.ReadPublicEntityByNick(nick) returned error %s for nick %s; want entity for nick\n", err, nick)
		}
		entityList = append(entityList, *entity)
		publicEntityList = append(publicEntityList, *publicEntity)
	}

	// 3. check result
	if len(entityList) != len(nicklist) {
		t.Errorf("Number of read entities is not equal to the number of requests entities; want same number\n")
	}
	if len(entityList) != len(publicEntityList) {
		t.Errorf("Number of read entities is not equal for entities and public entities; want same number\n")
	}

	/*
		GET IDENTITY TOKEN
		with nick and password
	*/
	// provide nick and password and get identity token back
	identityToken, err := CheckIdentity(newEntity.Nick, newEntity.Password, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(entity.Nick, password, TEST_HOST) returned error %s; want identity token without error\n", err)
	}
	// receive an identity token to use later (without credentials)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token to the server and the server checks the identity token
	for i := 0; i <= 5; i++ {
		if !IsIdentityTokenValid(identityToken.Token, testHost) {
			t.Errorf("IsIdentityTokenValid(identityToken.Token, TEST_HOST) returned false (invalid identity); want true (identity token need to be valid)\n")
		}
	}

	/*
		GET IDENTITY TOKEN for AUTHVALUE
		The client send an authorization value in the header of the http request
		Authorization:embiam based64-encoded-string from nick:password, e.g. "Authorization:embiam TEFDVlVLQko6RHJIWGhNdjd1QisuQ3hjNg=="
		this value contains the (no crypted) credetials and can be used directly.
	*/
	// simulate authValue
	authValue := "embiam " + base64.StdEncoding.EncodeToString([]byte(newEntity.Nick+":"+newEntity.Password))
	// get identityToken with authValue
	identityToken, returnNick, err := CheckAuthIdentity(authValue, testHost)
	if err != nil {
		t.Errorf("CheckAuthIdentity(authValue, TEST_HOST) with authValue %s returned error %s; want identity token without error\n", authValue, err)
	}
	if returnNick != newEntity.Nick {
		t.Errorf("IsAuthIdentityTokenValid(authValue, TEST_HOST) returned false nick %s; want correct nick %s\n", returnNick, newEntity.Nick)
	}

	// check identityToken from Authorizantion header
	// Authorization:embiam based64-encoded-string from identityToken, e.g. "Authorization:embiam TEFDVlVLQko6RHJIWGhNdjd1QisuQ3hjNg=="
	authValue = "embiam " + base64.StdEncoding.EncodeToString([]byte(identityToken.Token))
	for i := 0; i <= 5; i++ {
		if !IsAuthIdentityTokenValid(authValue, testHost) {
			t.Errorf("IsAuthIdentityTokenValid(authValue, TEST_HOST) returned false; want true\n")
		}
	}

	/*
		SIGN IN WITH WRONG CREDETIALS
		After a sign in with wrong credentials the number of false attempts is increased. Also the time of the wrong attempt is logged.
	*/
	_, err = CheckIdentity(newEntity.Nick, `Wr0ngPassWord`, testHost)
	if err == nil {
		t.Errorf("CheckIdentity(entity.Nick, `Wr0ngPassWord`, TEST_HOST) returned NO error; want error\n")
	}
	e, err := Db.ReadEntityByNick(newEntity.Nick)
	if err != nil {
		t.Errorf("Db.ReadEntityByNick(entity.Nick) for %s returned error %s; want entity without error\n", newEntity.Nick, err)
	}
	if e.WrongPasswordCounter != 1 {
		t.Errorf("e.WrongPasswordCounter = %d; want 1", e.WrongPasswordCounter)
	}

	/*
		LOCK ENTITY
		After serveral wrong sign in attempts the entity is locked.
		The number of attempts can be configured, check embiam.Configuration.MaxSignInAttempts
		The entity is locked by setting Entity.Active to false.
	*/
	for i := 0; i <= Configuration.MaxSignInAttempts; i++ {
		_, err = CheckIdentity(newEntity.Nick, `Wr0ngPassWord`, testHost)
		if err == nil {
			t.Errorf("CheckIdentity(entity.Nick, `Wr0ngPassWord`, TEST_HOST) returned NO error; want error")
		}
	}
	e, err = Db.ReadEntityByNick(newEntity.Nick)
	if err != nil {
		t.Errorf("Db.ReadEntityByNick(entity.Nick) for %s returned error %s; want entity without error", newEntity.Nick, err)
	}
	if e.Active {
		t.Errorf("e.Active = true; want false")
	}
	if e.WrongPasswordCounter != Configuration.MaxSignInAttempts+1 {
		t.Errorf("e.WrongPasswordCounter = %d; want %d", e.WrongPasswordCounter, Configuration.MaxSignInAttempts+1)
	}

	/*
		DELETE ENTITY
		The entities are moved to folder deleted in the folder of entities
	*/
	err = Db.DeleteEntity(newEntity.Nick)
	if err != nil {
		t.Errorf("Db.DeleteEntity(newEntity.Nick) for %s returned error %s; want delete without error", newEntity.Nick, err)
	}
}
