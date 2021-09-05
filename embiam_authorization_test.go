package embiam

import (
	"fmt"
	"log"
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

	db := new(DbTransient)
	Initialize(db)

	// create example roleMap
	roleExample := RoleCacheMap{
		"embiam.admin": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "embiam",
					Action:    ActionMap{ActionAsteriks: {}},
				},
			},
		},
		"embiam.reader": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "embiam",
					Action:    ActionMap{"read": {}},
				},
			},
		},
	}

	// save roles
	err := SaveRoles(roleExample)
	if err != nil {
		t.Errorf("db.SaveRoles(&roles) returned error %s; want no error\n", err)
	}
	if len(roleCache) == 0 {
		t.Errorf("len(roleCache) == 0; want prepared roles\n")
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
		t.Errorf("CheckIdentity(entity1.Nick, testPassword, testHost) returned error %s ; want identity token\n", err)
	}
	identityToken2, err := CheckIdentity(entity2.Nick, testPassword, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(entity2.Nick, testPassword, testHost) returned error %s ; want identity token\n", err)
	}
	identityToken3, err := CheckIdentity(entity3.Nick, testPassword, testHost)
	if err == nil {
		t.Errorf("CheckIdentity(entity3.Nick, testPassword, testHost) returned error %s ; want identity token\n", err)
	}

	// check authorization for entity 1
	if !IsAuthorized(identityToken1.Token, "embiam", "read") {
		t.Errorf("IsAuthorized(identityToken1.Token, embiam.entity, read) returned true; want false\n")
	}
	if IsAuthorized(identityToken1.Token, "embiam", "write") {
		t.Errorf("IsAuthorized(identityToken1.Token, embiam.entity, write) returned false; want true\n")
	}
	if IsAuthorized(identityToken1.Token, "embiam", "*") {
		t.Errorf("IsAuthorized(identityToken1.Token, embiam.entity, *) returned false; want true\n")
	}

	// check authorization for entity 2
	if !IsAuthorized(identityToken2.Token, "embiam", "read") {
		t.Errorf("IsAuthorized(identityToken2.Token, embiam.entity, read) returned false; want true\n")
	}
	if !IsAuthorized(identityToken2.Token, "embiam", "write") {
		t.Errorf("IsAuthorized(identityToken2.Token, embiam.entity, write) returned false; want true\n")
	}
	if !IsAuthorized(identityToken2.Token, "embiam", "*") {
		t.Errorf("IsAuthorized(identityToken2.Token, embiam.entity, *b) returned false; want true\n")
	}

	// check authorization for entity 3
	if IsAuthorized(identityToken3.Token, "embiam", "read") {
		t.Errorf("IsAuthorized(identityToken3.Token, embiam.entity, read) returned false; want true\n")
	}
	if IsAuthorized(identityToken3.Token, "embiam", "write") {
		t.Errorf("IsAuthorized(identityToken3.Token, embiam.entity, write) returned false; want true\n")
	}
	if IsAuthorized(identityToken3.Token, "embiam", "*") {
		t.Errorf("IsAuthorized(identityToken3.Token, embiam.entity, *b) returned false; want true\n")
	}

	// create example roleMap
	roleExample = RoleCacheMap{
		"a.all": {
			ContainedRole: []RoleIdType{"a.r", "a.w", "a.*"},
		},
		"a.r": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "a",
					Action:    ActionMap{"read": {}},
				},
			},
		},
		"a.w": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "a",
					Action:    ActionMap{"write": {}},
				},
			},
		},
		"a.*": {
			Authorization: []AuthorizationStruct{
				{
					Ressource: "a",
					Action:    ActionMap{ActionAsteriks: {}},
				},
			},
		},
	}

	// save roles
	err = SaveRoles(roleExample)
	if err != nil {
		t.Errorf("db.SaveRoles(&roles) returned error %s; want no error\n", err)
	}
	if len(roleCache) == 0 {
		t.Errorf("len(roleCache) == 0; want prepared roles\n")
	}

	// create new Entity 4 with a.rw
	entity4 := Entity{
		Nick:                 fmt.Sprintf(nickPattern, 3),
		PasswordHash:         Hash(testPassword),
		SecretHash:           Hash(`SeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEtSeCrEt`),
		Active:               true,
		WrongPasswordCounter: 0,
		LastSignInAttempt:    time.Time{},
		LastSignIn:           time.Now().UTC(),
		CreateTimeStamp:      time.Time{},
		UpdateTimeStamp:      time.Time{},
		Roles:                []RoleIdType{"a.all"},
	}
	err = db.SaveEntity(&entity4)
	if err != nil {
		t.Errorf("Db.SaveEntity(&entity4) returned error %s; want save entity without error\n", err)
	}

	// Sign in with correct credentials
	identityToken4, err := CheckIdentity(entity4.Nick, testPassword, testHost)
	if err != nil {
		t.Errorf("CheckIdentity(testNick, testPassword, testHost) returned error %s ; want identity token\n", err)
	}

	if !IsAuthorized(identityToken4.Token, "a", "read") {
		t.Errorf("IsAuthorized(dentityToken4.Token, a, read) returned false; want true\n")
	}
	if !IsAuthorized(identityToken4.Token, "a", "write") {
		t.Errorf("IsAuthorized(identityToken4.Token, a, write) returned false; want true\n")
	}
	if !IsAuthorized(identityToken4.Token, "a", "delete") {
		t.Errorf("IsAuthorized(identityToken4.Token, a, delete) returned false; want true\n")
	}
	if !IsAuthorized(identityToken4.Token, "a", string(ActionAsteriks)) {
		t.Errorf("IsAuthorized(identityToken4.Token, a, *) returned false; want true\n")
	}
}

func TestAuthDefaultRolesTransient(t *testing.T) {
	// initialize embiam
	Initialize(new(DbTransient))

	// 1. generate entity token (they are provided by the adminitrator and used by the user to generate the entity)
	entityToken, err := NewEntityToken()
	if err != nil {
		t.Errorf("NewEntityToken() returned error %s; want no error\n", err)
	}

	// 2. use entity token to generate entity
	newEntity, err := NewEntity(entityToken.Token, entityToken.Pin)
	if err != nil {
		t.Errorf("NewEntity(...) returned error %s; want no error\n", err)
	}
	// check if new entity has default role
	if newEntity.Roles[0] != `application` {
		t.Errorf("newEntity.Roles[0] != 'application'; want default role `application`\n")
	}
	// get identity token
	identityToken, err := CheckIdentity(newEntity.Nick, newEntity.Password, `me`)
	if err != nil {
		t.Errorf("CheckIdentity(...)returned error %s; want no error\n", err)
	}
	// check authorization
	if !IsAuthorized(identityToken.Token, `application`, `use`) {
		t.Errorf("IsAuthorized(identityToken, `application`, `use` returned false; want true\n")
	}
}

func TestRolesCheck(t *testing.T) {
	// initialize embiam
	Initialize(new(DbTransient))

	// check #1
	roleCache = RoleCacheMap{}
	err := roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #1 ) returned error %s; want no error\n", err)
	}

	// check #2
	roleCache = RoleCacheMap{
		`a`: {},
	}
	err = roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #2 ) returned error %s; want no error\n", err)
	}

	// check #3
	roleCache = RoleCacheMap{
		`a`: {ContainedRole: []RoleIdType{}},
	}
	err = roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #3 ) returned error %s; want no error\n", err)
	}

	// check #4
	roleCache = RoleCacheMap{
		`a`: {ContainedRole: []RoleIdType{`a`}},
	}
	err = roleCache.checkConsistency()
	if err == nil {
		t.Errorf("roleCache.checkConsistency( #4 ) returned NO error; want error for cycle\n")
	}

	// check #5
	roleCache = RoleCacheMap{
		`a`: {ContainedRole: []RoleIdType{`b`}},
		`b`: {},
	}
	err = roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #5 ) returned error %s; want no error\n", err)
	}

	// check #6
	roleCache = RoleCacheMap{
		`a`: {ContainedRole: []RoleIdType{`b`}},
		`b`: {ContainedRole: []RoleIdType{`c`}},
		`c`: {},
	}
	err = roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #6 ) returned error %s; want no error\n", err)
	}

	// check #7
	roleCache = RoleCacheMap{
		`a`: {ContainedRole: []RoleIdType{`b`}},
		`b`: {ContainedRole: []RoleIdType{`c`}},
		`c`: {},
	}
	err = roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #6 ) returned error %s; want no error\n", err)
	}

	// check #8
	roleCache = RoleCacheMap{
		`a`: {ContainedRole: []RoleIdType{`b`, `c`}},
		`b`: {ContainedRole: []RoleIdType{`d`}},
		`c`: {ContainedRole: []RoleIdType{`d`}},
		`d`: {},
	}
	err = roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #8 ) returned error %s; want no error\n", err)
	}

	// check #9
	roleCache = RoleCacheMap{
		`a`: {ContainedRole: []RoleIdType{`b`, ``}},
	}
	err = roleCache.checkConsistency()
	if err == nil {
		t.Errorf("roleCache.checkConsistency( #9 ) returned no error; want no error for empty role\n")
	}

	// check #10
	roleCache = RoleCacheMap{
		`a`:       {ContainedRole: []RoleIdType{`a.b`, `a.c`}},
		`a.b`:     {ContainedRole: []RoleIdType{`a.c.f.x`}},
		`a.c`:     {ContainedRole: []RoleIdType{`a.*.d`, `a.c.e`, `a.c.f`}},
		`a.*.d`:   {ContainedRole: []RoleIdType{`a.*.d.o`}},
		`a.*.d.o`: {},
		`a.c.e`:   {},
		`a.c.f`:   {ContainedRole: []RoleIdType{`a.c.f.x`, `a.c.f.y`}},
		`a.c.f.x`: {},
		`a.c.f.y`: {},
	}
	err = roleCache.checkConsistency()
	if err != nil {
		t.Errorf("roleCache.checkConsistency( #10 ) returned error %s; want no error\n", err)
	}

}

func TestAuthNewEntity(t *testing.T) {
	// initialize embiam
	db := new(DbFile)
	Initialize(db)

	/*
	   GENERATE ENTITY (users)
	   following the usual process:
	   1. the admin generates an entity token and provides it to the user
	   2. the user creates his personal entity using the entity token
	*/
	// 1. generate entity token (they are provided by the adminitrator and used by the user to generate the entity)
	entityToken, err := NewEntityToken()
	if err != nil {
		t.Errorf("NewEntityToken() returned error %s; want no error\n", err)
	}

	// 2. use entity token to generate entity
	newEntity, err := NewEntity(entityToken.Token, entityToken.Pin)
	if err != nil {
		t.Errorf("NewEntity(entityToken.Token, entityToken.Pin) returned error %s; want no error\n", err)
	}
	// check if new entity has default role
	if newEntity.Roles[0] != "application" {
		t.Errorf("newEntity.Roles[1] != 'application'; want default role 'application'\n")
		return
	}

	/*
		GET IDENTITY TOKEN
		from nick and password
	*/
	// provide nick and password and get identity token back
	identityToken, err := CheckIdentity(newEntity.Nick, newEntity.Password, "localhost")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Identity of %s was validated. The identity token %s was provided\n\n", newEntity.Nick, identityToken.Token)
	// receive an identity token to use later (without credentials)

	// With the provided identity token, the user can e.g. call APIs
	// When an API is called, the client passes the identity token  to the server.
	// The server checks the identity token
	if IsIdentityTokenValid(identityToken.Token, "localhost") {
		fmt.Printf("Identity token is valid.\n\n")
	} else {
		log.Fatalln(err)
	}
}
