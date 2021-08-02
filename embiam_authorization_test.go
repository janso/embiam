package embiam

import (
	"encoding/json"
	"testing"
)

func TestAuthNode(t *testing.T) {
	model := new(DbFile)
	Initialize(model)

	// create test data and save it
	authNodeJson := `
	[{
		"id":"embiam.entity.all",
		"node":["embiam.entityToken.all"],
		"authorization":{
			"activity":["*"]
		}
	},
	{
		"id":"embiam.entity.provider",
		"node":["embiam.entity.viewer","embiam.entityToken.all"],
		"authorization":{
			"activity":["read", "reactivate"]
		}
	},
	{
		"Id":"embiam.entity.viewer",
		"authorization":{
			"activity":["read"]
		}
	},
	{
		"id":"embiam.entityToken.all",
		"authorization":{
			"activity":["*"]
		}
	}]`

	authNodes := new([]AuthNodeStruct)
	err := json.Unmarshal([]byte(authNodeJson), authNodes)
	if err != nil {
		t.Errorf("in signIn() function CheckIdentity(nick, TestPassword, host) returned error %s ; want identity token", err)
	}
	err = model.SaveAuthNodes(authNodes)
	if err != nil {
		t.Errorf("Error saving authorization nodes %s; want save without error\n", err)
	}

	// load test data
	authNodes = new([]AuthNodeStruct)
	err = model.ReadAuthNodes(authNodes)
	if err != nil {
		t.Errorf("Error loading authorization nodes %s; want save without error\n", err)
	}

	// t.Logf("%s\n", authNodes)
}
