package embiam

type AuthLeafStruct struct {
	Ressource     string `json:"ressource"`
	Authorization map[string][]string
}

// IsAuthorized checks if the entity, provides through token, is authorizied for authLeaf
func IsAuthorized(token string, authLeaf AuthLeafStruct) bool {
	return false
}
