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
	Initialize(new(DbMock))

	// Generate test entities
	for i := 1; i <= nickCount; i++ {
		nick := fmt.Sprintf(nickPattern, i)
		GenerateAndSaveMockEntity(nick, testPassword, `SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`)
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
