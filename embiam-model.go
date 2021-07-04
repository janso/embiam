package embiam

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

/*
	*******************************************************************
		Model
	*******************************************************************
*/
var Db DbInterface

type DbInterface interface {
	Initialize()
	LoadConfiguration() (ConfigurationStruct, error)
	InitializeConfiguration()
	ReadEntityByNick(nick string) (*Entity, error)
	EntityExists(nick string) bool
	SaveEntity(entity *Entity) error
	SaveEntityToken(entityToken *EntityToken) error
	ReadEntityToken(tokenoken string) (*EntityToken, error)
	DeleteEntityToken(token string) error
}

/*
	DbMock
*/
type DbMock struct {
	entityStore      map[string]Entity
	entityTokenStore map[string]EntityToken
}

func (m *DbMock) Initialize() {
	m.entityStore = make(map[string]Entity, 32)
}

func (m DbMock) LoadConfiguration() (ConfigurationStruct, error) {
	conf := ConfigurationStruct{
		Port:                         "8242",
		DBPath:                       "",
		IdentityTokenValiditySeconds: 720,
		MaxSignInAttempts:            3,
	}
	return conf, nil
}

func (m *DbMock) InitializeConfiguration() {
}

func (m DbMock) ReadEntityByNick(nick string) (*Entity, error) {
	e, found := m.entityStore[nick]
	if found {
		return &e, nil
	}
	return nil, errors.New("entity not found")
}

func (m DbMock) EntityExists(nick string) bool {
	_, found := m.entityStore[nick]
	return found
}

func (m DbMock) SaveEntity(e *Entity) error {
	m.entityStore[e.Nick] = *e
	return nil
}

func (m DbMock) SaveEntityToken(et *EntityToken) error {
	m.entityTokenStore[et.Token] = *et
	return nil
}

func (m DbMock) ReadEntityToken(token string) (*EntityToken, error) {
	et, found := m.entityTokenStore[token]
	if found {
		return &et, nil
	}
	return nil, errors.New("entity token not found")
}

func (m DbMock) DeleteEntityToken(token string) error {
	delete(m.entityTokenStore, token)
	return nil
}

/*
	DbFile
*/

const EntityFilePath = `entity/`
const EntityTokenFilePath = `entityToken/`

type DbFile struct{}

func (m *DbFile) Initialize() {
}

func (m DbFile) LoadConfiguration() (ConfigurationStruct, error) {
	const ConfigurationFileName = "conf.json"

	// set defaults
	conf := ConfigurationStruct{
		Port:                         "8242",
		DBPath:                       "db/",
		IdentityTokenValiditySeconds: 720,
		MaxSignInAttempts:            3,
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

func (m *DbFile) InitializeConfiguration() {
	// create directories in db/
	folderPath := Configuration.DBPath + EntityFilePath
	err := os.MkdirAll(folderPath, os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}
	folderPath = Configuration.DBPath + EntityTokenFilePath
	err = os.MkdirAll(folderPath, os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}
}

func (m DbFile) ReadEntityByNick(nick string) (*Entity, error) {
	filepath := Configuration.DBPath + EntityFilePath + nick
	jsonString, err := ioutil.ReadFile(filepath)
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

func (m DbFile) EntityExists(nick string) bool {
	filepath := Configuration.DBPath + EntityFilePath + nick
	_, err := os.Stat(filepath)
	return err == nil
}

func (m DbFile) SaveEntity(e *Entity) error {
	filepath := Configuration.DBPath + EntityFilePath + e.Nick
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

func (m DbFile) SaveEntityToken(et *EntityToken) error {
	filepath := Configuration.DBPath + EntityTokenFilePath + et.Token
	jsonbytes, err := json.MarshalIndent(et, "", "\t")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath, jsonbytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (m DbFile) ReadEntityToken(token string) (*EntityToken, error) {
	filepath := Configuration.DBPath + EntityTokenFilePath + token
	jsonString, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, errors.New("entity token not found " + token)
	}
	et := EntityToken{}
	err = json.Unmarshal([]byte(jsonString), &et)
	if err != nil {
		return nil, err
	}
	return &et, nil
}

func (m DbFile) DeleteEntityToken(token string) error {
	filepath := Configuration.DBPath + EntityTokenFilePath + token
	err := os.Remove(filepath)
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
	EntityTokenValidityHours     int    `json:"entityTokenValidityHours"`
	IdentityTokenValiditySeconds int    `json:"identityTokenValiditySeconds"`
	MaxSignInAttempts            int    `json:"maxSignInAttempts"`
}
