package embiam

import (
	"encoding/json"
	"testing"
)

func TestAuthNode(t *testing.T) {
	anEntityToken := AuthNodeStruct{
		Id:            "embiam.entityToken",
		Children:      []string{},
		Authorization: map[string][]string{},
	}
	anEntityToken.Authorization["dataObject"] = []string{"entityToken"}
	anEntityToken.Authorization["activity"] = []string{"get"}

	anEntityViewer := AuthNodeStruct{
		Id:            "embiam.entity.viewer",
		Children:      []string{},
		Authorization: map[string][]string{},
	}
	anEntityViewer.Authorization["dataObject"] = []string{"entity"}
	anEntityViewer.Authorization["activity"] = []string{"read"}
	jsonbytes, err := json.Marshal(anEntityViewer)
	if err != nil {
		panic(err)
	}
	t.Logf("%s\n", jsonbytes)

	anEntityProvider := AuthNodeStruct{
		Id:            "embiam.entity.provider",
		Children:      []string{},
		Authorization: map[string][]string{},
	}
	anEntityViewer.Children = []string{"embiam.entity.viewer", "embiam.entityToken"}
	anEntityViewer.Authorization["dataObject"] = []string{"entity"}
	anEntityProvider.Authorization["activity"] = []string{"read", "reactivate"}

	jsonbytes, err = json.Marshal(anEntityProvider)
	if err != nil {
		panic(err)
	}
	t.Logf("%s\n", jsonbytes)

	anEntityAdmin := AuthNodeStruct{
		Id:            "embiam.admin",
		Children:      []string{},
		Authorization: map[string][]string{},
	}
	anEntityAdmin.Children = append(anEntityAdmin.Children, "embiam.viewer", "embiam.entityProvider")

	jsonbytes, err = json.Marshal(anEntityAdmin)
	if err != nil {
		panic(err)
	}
	t.Logf("%s\n", jsonbytes)
}
