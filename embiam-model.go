package embiam

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

/*
	*******************************************************************
		EntityModel
	*******************************************************************
*/
var entityModel EntityModelInterface

type EntityModelInterface interface {
	LoadConfiguration() (ConfigurationStruct, error)
	ReadByNick(nick string) (*Entity, error)
	NickExists(nick string) bool
	Save(entity *Entity) error
}

/*
	EntityModelMock
*/
type EntityModelMock struct{}

func (m EntityModelMock) LoadConfiguration() (ConfigurationStruct, error) {
	conf := ConfigurationStruct{
		Port:                         "8288",
		DBPath:                       "db/",
		IdentityTokenValiditySeconds: 720,
	}
	return conf, nil
}

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

/*
	EntityModelFileDB
*/
type EntityModelFileDB struct{}

func (m EntityModelFileDB) LoadConfiguration() (ConfigurationStruct, error) {
	const ConfigurationFileName = "conf.json"

	// set defaults
	conf := ConfigurationStruct{
		Port:                         "8242",
		DBPath:                       "db/",
		IdentityTokenValiditySeconds: 720,
	}

	// get directory of executable as basis for relativ paths
	executableDirectory, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("Error %s\n", err)
	}
	// read configuration file from executables directory
	filedir := executableDirectory + "/" + ConfigurationFileName
	jsonbytes, err := ioutil.ReadFile((filedir))
	if err != nil {
		log.Fatalf("Error reading configuration file %s: '%s'\n", filedir, err)
	}
	// parse json
	err = json.Unmarshal([]byte(jsonbytes), &conf)
	if err != nil {
		log.Fatalf("Error parsing configuration file %s: '%s'\n", filedir, err)
	}
	// complete db path (if the path is realtive make it absolute by add the directory of the executable)
	if !filepath.IsAbs(conf.DBPath) {
		// make relativ path absolut
		conf.DBPath = executableDirectory + "/" + conf.DBPath
	}
	// if db path is initial, set to default "db/""
	if len(conf.DBPath) == 0 {
		conf.DBPath = "db/"
	}
	// check if db path exists
	_, err = os.Stat(conf.DBPath)
	if err != nil {
		log.Fatalf("Error: DBPath does not exitst '%s'\n", conf.DBPath)
	}
	// make sure that db path ends with /
	if conf.DBPath[len(conf.DBPath)-1:] != "/" {
		conf.DBPath = conf.DBPath + "/"
	}

	return conf, nil // ToDo: return pointer to increase efficiency (does it really increase efficiency?)
}

func (m EntityModelFileDB) ReadByNick(nick string) (*Entity, error) {
	filepath := Configuration.DBPath + nick
	jsonString, err := ioutil.ReadFile((filepath))
	if err != nil {
		return nil, err
	}
	entity := Entity{}
	err = json.Unmarshal([]byte(jsonString), &entity)
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func (m EntityModelFileDB) NickExists(nick string) bool {
	filepath := Configuration.DBPath + nick
	_, err := os.Stat(filepath)
	return err == nil
}

func (m EntityModelFileDB) Save(e *Entity) error {
	filepath := Configuration.DBPath + e.Nick
	jsonbytes, err := json.MarshalIndent(e, "", "\t")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath, jsonbytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

/*
	*******************************************************************
		Configuration
	*******************************************************************
*/
var Configuration ConfigurationStruct

type ConfigurationStruct struct {
	Port                         string `json:"port"`
	DBPath                       string `json:"dbPath"`
	IdentityTokenValiditySeconds int32  `json:"identityTokenValiditySeconds"`
}
