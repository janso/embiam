package embiam

import (
	"fmt"
	"testing"
	"time"
)

func TestRessource(t *testing.T) {
	resA := RessourceType("*")
	resB := RessourceType("")
	if !resA.contains(resB) {
		t.Errorf("'*'.contains('') returned false; want true\n")
	}
	resA = RessourceType("")
	resB = RessourceType("")
	if !resA.contains(resB) {
		t.Errorf("''.contains('') returned false; want true\n")
	}
	resA = RessourceType("")
	resB = RessourceType("x")
	if resA.contains(resB) {
		t.Errorf("''.contains('x') returned false; want true\n")
	}
	resA = RessourceType("*")
	resB = RessourceType("x")
	if !resA.contains(resB) {
		t.Errorf("'*'.contains('x') returned false; want true\n")
	}
	if resB.contains(resA) {
		t.Errorf("'x'.contains('*') returned true; want false\n")
	}
	resA = RessourceType("x")
	resB = RessourceType("y")
	if resA.contains(resB) {
		t.Errorf("'x'.contains('y') returned false; want true\n")
	}
	if resB.contains(resA) {
		t.Errorf("'y'.contains('x') returned true; want false\n")
	}
	resA = RessourceType("embiam.*")
	resB = RessourceType("embiam.entity")
	if !resA.contains(resB) {
		t.Errorf("resA.contains(resB) returned false; want true\n")
	}
	if resB.contains(resA) {
		t.Errorf("resB.contains(resA) returned true; want false\n")
	}
	resA = RessourceType("embiam.*")
	resB = RessourceType("embiam.entity")
	if !resA.contains(resB) {
		t.Errorf("resA.contains(resB) returned false; want true\n")
	}
	if resB.contains(resA) {
		t.Errorf("resB.contains(resA) returned true; want false\n")
	}
}

func TestAuth(t *testing.T) {
	const (
		testPassword = `PaSsWoRdPaSsWoRd`
		nickPattern  = "N1CK%04d"
	)

	db := new(DbFile)
	Initialize(db)

	// create example roleMap
	roleExample := RoleCacheMap{
		"embiam.admin": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "embiam.*",
					Action:    ActionMap{ActionAsteriks: {}},
				},
			},
		},
		"embiam.reader": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "embiam.*",
					Action:    ActionMap{"read": {}},
				},
			},
		},
	}

	// save roles
	err := db.SaveRoles(roleExample)
	if err != nil {
		t.Errorf("db.SaveRoles(&roles) returned error %s; want no error\n", err)
	}

	// load them (to roleCache)
	roleCache, err = db.ReadRoles()
	if err != nil {
		t.Errorf("db.ReadRoles(&roles) returned error %s; want no error\n", err)
	}
	if roleCache == nil {
		t.Errorf("db.ReadRoles(&roles) returned no roles; want prepared roles\n")
	}

	// generate example entity with role embiam.reader

	entity1 := Entity{
		Nick:                 fmt.Sprintf(nickPattern, 1),
		PasswordHash:         Hash(testPassword),
		SecretHash:           Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
		Active:               true,
		WrongPasswordCounter: 0,
		LastSignInAttempt:    time.Time{},
		LastSignIn:           time.Now().UTC(),
		CreateTimeStamp:      time.Time{},
		UpdateTimeStamp:      time.Time{},
		Roles:                []RoleIdType{"embiam.reader"},
	}
	err = db.SaveEntity(&entity1)
	if err != nil {
		t.Errorf("Db.SaveEntity(&entity1) returned error %s; want save entity without error\n", err)
	}

	entity2 := Entity{
		Nick:                 fmt.Sprintf(nickPattern, 2),
		PasswordHash:         Hash(testPassword),
		SecretHash:           Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
		Active:               true,
		WrongPasswordCounter: 0,
		LastSignInAttempt:    time.Time{},
		LastSignIn:           time.Now().UTC(),
		CreateTimeStamp:      time.Time{},
		UpdateTimeStamp:      time.Time{},
		Roles:                []RoleIdType{"embiam.admin"}, // admin role
	}
	err = db.SaveEntity(&entity2)
	if err != nil {
		t.Errorf("Db.SaveEntity(&entity2) returned error %s; want save entity without error\n", err)
	}

	entity3 := Entity{
		Nick:                 fmt.Sprintf(nickPattern, 3),
		PasswordHash:         Hash(testPassword),
		SecretHash:           Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
		Active:               true,
		WrongPasswordCounter: 0,
		LastSignInAttempt:    time.Time{},
		LastSignIn:           time.Now().UTC(),
		CreateTimeStamp:      time.Time{},
		UpdateTimeStamp:      time.Time{},
		Roles:                []RoleIdType{"embiam.reader", "role.noexisting"},
	}
	err = db.SaveEntity(&entity3)
	if err != nil {
		t.Errorf("Db.SaveEntity(&entity3) returned error %s; want save entity without error\n", err)
	}

	// Sign in with correct credentials
	identityToken1, err := CheckIdentity(entity1.Nick, testPassword, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(testNick, testPassword, testHost) returned error %s ; want identity token\n", err)
	}
	identityToken2, err := CheckIdentity(entity2.Nick, testPassword, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(testNick, testPassword, testHost) returned error %s ; want identity token\n", err)
	}
	identityToken3, err := CheckIdentity(entity3.Nick, testPassword, testHost)
	if err == nil {
		t.Errorf("CheckIdentity(testNick, testPassword, testHost) returned error %s ; want identity token\n", err)
	}

	// check authorization for entity 1
	if !IsAuthorized(identityToken1.Token, "embiam.entity", "read") {
		t.Errorf("IsAuthorized(identityToken1.Token, embiam.entity, read) returned false; want true\n")
	}
	if IsAuthorized(identityToken1.Token, "embiam.entity", "write") {
		t.Errorf("IsAuthorized(identityToken1.Token, embiam.entity, write) returned true; want false\n")
	}
	if IsAuthorized(identityToken1.Token, "embiam.entity", "*") {
		t.Errorf("IsAuthorized(identityToken1.Token, embiam.entity, *b) returned true; want false\n")
	}
	if !IsAuthorized(identityToken1.Token, "embiam.marmelquark", "read") {
		t.Errorf("IsAuthorized(identityToken1.Token, embiam.marmelquark, read) returned false; want true\n")
	}

	// check authorization for entity 2
	if !IsAuthorized(identityToken2.Token, "embiam.entity", "read") {
		t.Errorf("IsAuthorized(identityToken2.Token, embiam.entity, read) returned false; want true\n")
	}
	if !IsAuthorized(identityToken2.Token, "embiam.entity", "write") {
		t.Errorf("IsAuthorized(identityToken2.Token, embiam.entity, write) returned false; want true\n")
	}
	if !IsAuthorized(identityToken2.Token, "embiam.entity", "*") {
		t.Errorf("IsAuthorized(identityToken2.Token, embiam.entity, *b) returned false; want true\n")
	}
	if !IsAuthorized(identityToken2.Token, "embiam.admin", "read") {
		t.Errorf("IsAuthorized(identityToken2.Token, embiam.admin, read) returned false; want true\n")
	}

	// check authorization for entity 3
	if IsAuthorized(identityToken3.Token, "embiam.entity", "read") {
		t.Errorf("IsAuthorized(identityToken.Token3, embiam.entity, read) returned false; want true\n")
	}
	if IsAuthorized(identityToken3.Token, "embiam.entity", "write") {
		t.Errorf("IsAuthorized(identityToken.Token3, embiam.entity, write) returned true; want false\n")
	}
	if IsAuthorized(identityToken3.Token, "embiam.entity", "*") {
		t.Errorf("IsAuthorized(identityToken.Token3, embiam.entity, *b) returned true; want false\n")
	}
	if IsAuthorized(identityToken3.Token, "embiam.admin", "read") {
		t.Errorf("IsAuthorized(identityToken.Token3, embiam.admin, read) returned true; want false\n")
	}
}
