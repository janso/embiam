package embiam

/*
	*******************************************************************
		EntityModel
	*******************************************************************
*/
var entityModel EntityModelInterface

type EntityModelInterface interface {
	ReadByNick(nick string) (*Entity, error)
	NickExists(nick string) bool
	Save(entity *Entity) error
	LoadConfiguration() (ConfigurationStruct, error)
}

/*
	EntityModelMock
*/
type EntityModelMock struct{}

func (m EntityModelMock) ReadByNick(nick string) (*Entity, error) {
	e := Entity{}
	e.Nick = nick
	e.PasswordHash = Hash("SeCrEtSeCrEt")
	return &e, nil
}

func (m EntityModelMock) NickExists(nick string) bool {
	if nick == "NICK4201" {
		return true
	} else if nick == "NICK4202" {
		return true
	} else if nick == "NICK4203" {
		return true
	}
	return false
}

func (m EntityModelMock) Save(e *Entity) error {
	return nil
}

func (m EntityModelMock) LoadConfiguration() (ConfigurationStruct, error) {
	conf := ConfigurationStruct{
		Port:                         "8288",
		DBPath:                       "/db/entity",
		IdentityTokenValidityMinutes: 12,
	}
	return conf, nil
}

/*
	*******************************************************************
		Configuration
	*******************************************************************
*/
var configuration ConfigurationStruct

type ConfigurationStruct struct {
	Port                         string `json:"port"`
	DBPath                       string `json:"dbPath"`
	IdentityTokenValidityMinutes int32  `json:"identityTokenValidityMinutes"`
}
