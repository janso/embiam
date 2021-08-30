package embiam

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

/********************************************************************
	Interface Db (database, persistent storage)
********************************************************************/
var Db DbInterface

type DbInterface interface {
	Initialize()
	// Entity
	ReadEntityList() (nicklist []string, e error)
	ReadEntityByNick(nick string) (*Entity, error)
	ReadPublicEntityByNick(nick string) (*PublicEntity, error)
	EntityExists(nick string) bool
	SaveEntity(entity *Entity) error
	DeleteEntity(nick string) error

	// Entity Tokens
	SaveEntityToken(entityToken *EntityToken) error
	ReadEntityToken(tokenoken string) (*EntityToken, error)
	DeleteEntityToken(token string) error

	// Roles
	ReadRoles() (roleMap RoleMap, err error)
	SaveRoles(roleMap RoleMap) error
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

func (m DbTransient) ReadEntityList() (nicklist []string, e error) {
	nicklist = make([]string, len(m.entityStore))
	for _, entity := range m.entityStore {
		nicklist = append(nicklist, entity.Nick)
	}
	return nicklist, nil
}

func (m DbTransient) ReadEntityByNick(nick string) (*Entity, error) {
	e, found := m.entityStore[nick]
	if found {
		return &e, nil
	}
	return nil, errors.New("entity not found")
}

func (m DbTransient) ReadPublicEntityByNick(nick string) (*PublicEntity, error) {
	entity, err := m.ReadEntityByNick(nick)
	if err != nil {
		return nil, err
	}
	publicEntity := entity.ToPublicEntity()
	return &publicEntity, nil
}

func (m DbTransient) EntityExists(nick string) bool {
	_, found := m.entityStore[nick]
	return found
}

func (m DbTransient) SaveEntity(e *Entity) error {
	m.entityStore[e.Nick] = *e
	return nil
}

func (m DbTransient) DeleteEntity(nick string) error {
	delete(m.entityStore, nick)
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

func (m DbTransient) ReadRoles() (roleMap RoleMap, err error) {
	// ToDo: Implement
	return nil, nil
}

func (m DbTransient) SaveRoles(authNode RoleMap) error {
	// ToDo: Implement
	return nil
}

/*
	DbFile - use the filesystem and store json files
*/
type DbFile struct {
	EntityFilePath        string
	EntityDeletedFilePath string
	EntityTokenFilePath   string
	RolePath              string
	DBPath                string

	RoleFilename string
}

func (m *DbFile) Initialize() {
	// get directory of executable as basis for relativ paths
	executableDirectory, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("Error %s\n", err)
	}

	// set paths
	m.DBPath = executableDirectory + `/embiamDb/`
	m.EntityFilePath = m.DBPath + `entity/`
	m.EntityDeletedFilePath = m.DBPath + `entity/deleted/`
	m.EntityTokenFilePath = m.DBPath + `entityToken/`
	m.RolePath = m.DBPath + `role/`

	// create paths
	InitializeDirectory(m.EntityFilePath)
	InitializeDirectory(m.EntityDeletedFilePath)
	InitializeDirectory(m.EntityTokenFilePath)
	InitializeDirectory(m.RolePath)

	m.RoleFilename = `role.json`
}

func (m DbFile) ReadEntityList() (nicklist []string, e error) {
	files, err := ioutil.ReadDir(m.EntityFilePath)
	if err != nil {
		return nil, fmt.Errorf("error '%s' reading directory '%s'", err.Error(), m.EntityFilePath)
	}
	nicklist = make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		// ToDo: Improve and ignore hidden files
		filename := file.Name()
		// ToDo: Improve and check if only allowed characters are in filename
		if filename[0:1] == "." {
			continue
		}
		nicklist = append(nicklist, filename)

	}
	return nicklist, nil
}

func (m DbFile) ReadEntityByNick(nick string) (*Entity, error) {
	filepath := m.EntityFilePath + nick
	jsonString, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error '%s' reading file '%s'", err.Error(), filepath)
	}
	entity := Entity{}
	err = json.Unmarshal([]byte(jsonString), &entity)
	if err != nil {
		return nil, fmt.Errorf("error '%s' unmarshalling nick %s", err.Error(), nick)
	}
	return &entity, nil
}

func (m DbFile) ReadPublicEntityByNick(nick string) (*PublicEntity, error) {
	entity, err := m.ReadEntityByNick(nick)
	if err != nil {
		return nil, err
	}
	publicEntity := entity.ToPublicEntity()
	return &publicEntity, nil
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

func (m DbFile) DeleteEntity(nick string) error {
	oldFilepath := m.EntityFilePath + nick
	newFilepath := m.EntityDeletedFilePath + nick
	err := os.Rename(oldFilepath, newFilepath)
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

func (m DbFile) DeleteContentsFromDirectory(dir string) error {
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

func (m DbFile) ReadRoles() (roleMap RoleMap, err error) {
	roleMap = make(RoleMap)
	filepath := m.RolePath + m.RoleFilename
	jsonString, err := ioutil.ReadFile(filepath)
	if err != nil {
		return roleMap, err
	}
	err = json.Unmarshal([]byte(jsonString), &roleMap)
	if err != nil {
		return roleMap, err
	}
	return roleMap, nil
}

func (m DbFile) SaveRoles(roleMap RoleMap) error {
	jsonbytes, err := json.MarshalIndent(roleMap, "", "\t")
	if err != nil {
		return err
	}
	filepath := m.RolePath + m.RoleFilename
	os.Remove(filepath)
	err = ioutil.WriteFile(filepath, jsonbytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

// InitializeDirectory checks if 'folderPath' exists and creates it, if it's not existing
func InitializeDirectory(folderPath string) error {
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
