package embiam

type AuthNodeStruct struct {
	Id            string              `json:"ressource"`     // Id is the unique name of the authorization node
	Children      []string            `json:"node"`          // refers to other nodes to inherted their authorization
	Authorization map[string][]string `json:"authorization"` // actual authorisition
}

// IsAuthorized checks if the entity, provides through token, is authorizied for authLeaf
func IsAuthorized(token string, authLeaf AuthNodeStruct) bool {
	return false
}
