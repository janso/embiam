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
		Database (persistent storage)
	*******************************************************************
*/
var Db DbInterface

type DbInterface interface {
	Initialize()
	ReadEntityByNick(nick string) (*Entity, error)
	EntityExists(nick string) bool
	SaveEntity(entity *Entity) error
	SaveEntityToken(entityToken *EntityToken) error
	ReadEntityToken(tokenoken string) (*EntityToken, error)
	DeleteEntityToken(token string) error
}

/*
	DbTransient - non-persistent database for testing and demonstration
*/
type DbTransient struct {
	entityStore      map[string]Entity
	entityTokenStore map[string]EntityToken
}

func (m *DbTransient) Initialize() {
	m.entityStore = make(map[string]Entity, 32)
}

func (m DbTransient) ReadEntityByNick(nick string) (*Entity, error) {
	e, found := m.entityStore[nick]
	if found {
		return &e, nil
	}
	return nil, errors.New("entity not found")
}

func (m DbTransient) EntityExists(nick string) bool {
	_, found := m.entityStore[nick]
	return found
}

func (m DbTransient) SaveEntity(e *Entity) error {
	m.entityStore[e.Nick] = *e
	return nil
}

func (m DbTransient) SaveEntityToken(et *EntityToken) error {
	m.entityTokenStore[et.Token] = *et
	return nil
}

func (m DbTransient) ReadEntityToken(token string) (*EntityToken, error) {
	et, found := m.entityTokenStore[token]
	if found {
		return &et, nil
	}
	return nil, errors.New("entity token not found")
}

func (m DbTransient) DeleteEntityToken(token string) error {
	delete(m.entityTokenStore, token)
	return nil
}

/*
	DbFile - simple persistence use the filesystem and store json text files
*/

type DbFile struct {
	EntityFilePath      string
	EntityTokenFilePath string
	DBPath              string
}

func (m *DbFile) Initialize() {
	// get directory of executable as basis for relativ paths
	executableDirectory, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("Error %s\n", err)
	}

	// set paths
	m.DBPath = executableDirectory + `/db/`
	m.EntityFilePath = m.DBPath + `entity/`
	m.EntityTokenFilePath = m.DBPath + `entityToken/`

	// create paths
	initializeDirectory(m.EntityFilePath)
	initializeDirectory(m.EntityTokenFilePath)
}

func (m DbFile) ReadEntityByNick(nick string) (*Entity, error) {
	filepath := m.EntityFilePath + nick
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
	filepath := m.EntityFilePath + nick
	_, err := os.Stat(filepath)
	return err == nil
}

func (m DbFile) SaveEntity(e *Entity) error {
	filepath := m.EntityFilePath + e.Nick
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
	filepath := m.EntityTokenFilePath + et.Token
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
	filepath := m.EntityTokenFilePath + token
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
	filepath := m.EntityTokenFilePath + token
	err := os.Remove(filepath)
	if err != nil {
		return err
	}
	return nil
}

func (m DbFile) DeleteFilesFromDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func initializeDirectory(folderPath string) error {
	fileinfo, err := os.Stat(folderPath)
	if err == nil {
		if !fileinfo.IsDir() {
			return errors.New(folderPath + " is not a directory")
		}
		return nil
	}
	err = os.MkdirAll(folderPath, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}
