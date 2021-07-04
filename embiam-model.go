package embiam

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

type Storer interface {
	Init()
	List()
}

type StringStore struct {
	a []string
}

func (ss *StringStore) Init() {
	fmt.Printf("StringStore.Init()\n")
	ss.a = []string{"Hund", "Katze", "Maus"}
}

func (ss StringStore) List() {
	fmt.Printf("StringStore.List()\n")
	for _, s := range ss.a {
		fmt.Printf("  %s\n", s)
	}
}

/*
	*******************************************************************
		EntityModel
	*******************************************************************
*/
var entityModel EntityModelInterface

type EntityModelInterface interface {
	Initialize()
	LoadConfiguration() (ConfigurationStruct, error)
	InitializeConfiguration()
	ReadByNick(nick string) (*Entity, error)
	NickExists(nick string) bool
	Save(entity *Entity) error
}

/*
	EntityModelMock
*/
type EntityModelMock struct {
	entityStore map[string]Entity
}

func (m *EntityModelMock) Initialize() {
	m.entityStore = make(map[string]Entity, 32)
	// insert dummy entities
	for i := 1; i < 4; i++ {
		e := Entity{
			Nick:                 fmt.Sprintf("NICK%04d", i),
			PasswordHash:         Hash("SeCrEtSeCrEt"),
			SecretHash:           "",
			Active:               true,
			LastSignIn:           time.Time{},
			WrongPasswordCounter: 0,
			CreateTimeStamp:      time.Now().UTC(),
			UpdateTimeStamp:      time.Time{},
		}
		m.Save(&e)
	}
}

func (m EntityModelMock) LoadConfiguration() (ConfigurationStruct, error) {
	conf := ConfigurationStruct{
		Port:                         "8242",
		DBPath:                       "",
		IdentityTokenValiditySeconds: 720,
		MaxSignInAttempts:            3,
	}
	return conf, nil
}

func (m *EntityModelMock) InitializeConfiguration() {
}

func (m EntityModelMock) ReadByNick(nick string) (*Entity, error) {
	e, found := m.entityStore[nick]
	if found {
		return &e, nil
	}
	return nil, errors.New("nick not found")
}

func (m EntityModelMock) NickExists(nick string) bool {
	_, found := m.entityStore[nick]
	return found
}

func (m EntityModelMock) Save(e *Entity) error {
	m.entityStore[e.Nick] = *e
	return nil
}

/*
	EntityModelFileDB
*/

type EntityModelFileDB struct{}

func (m *EntityModelFileDB) Initialize() {
}

func (m EntityModelFileDB) LoadConfiguration() (ConfigurationStruct, error) {
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

func (m *EntityModelFileDB) InitializeConfiguration() {
	// create directories in db/
	folderPath := Configuration.DBPath + `nick/`
	err := os.MkdirAll(folderPath, os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}
	folderPath = Configuration.DBPath + `newNickToken/`
	err = os.MkdirAll(folderPath, os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}

}

func (m EntityModelFileDB) ReadByNick(nick string) (*Entity, error) {
	filepath := Configuration.DBPath + `nick/` + nick
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
	filepath := Configuration.DBPath + `nick/` + nick
	_, err := os.Stat(filepath)
	return err == nil
}

func (m EntityModelFileDB) Save(e *Entity) error {
	filepath := Configuration.DBPath + `nick/` + e.Nick
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
	IdentityTokenValiditySeconds int    `json:"identityTokenValiditySeconds"`
	MaxSignInAttempts            int    `json:"maxSignInAttempts"`
}
