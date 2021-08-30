package embiam

import (
	"testing"
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
	db := new(DbFile)
	Initialize(db)

	// create example roleMap
	roleCache := RoleCacheMap{
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

	err := db.SaveRoles(roleCache)
	if err != nil {
		t.Errorf("db.SaveRoles(&roles) returned error %s; want no error\n", err)
	}

	readRoles, err := db.ReadRoles()
	if err != nil {
		t.Errorf("db.ReadRoles(&roles) returned error %s; want no error\n", err)
	}
	if readRoles == nil {
		t.Errorf("db.ReadRoles(&roles) returned no roles; want prepared roles\n")
	}
}
