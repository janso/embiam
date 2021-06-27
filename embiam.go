package embiam

import (
	"errors"
	"log"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Entity describes a user or a device
type Entity struct {
	Nick                 string    `json:"nick"`
	PasswordHash         string    `json:"passwordHash"`
	SecretHash           string    `json:"secretHash"`
	Active               bool      `json:"active"`
	LastSingIn           time.Time `json:"lastSingIn"`
	WrongPasswordCounter int       `json:"WrongPasswordCounter"`
	CreateTimeStamp      time.Time `json:"createTimeStamp"`
	UpdateTimeStamp      time.Time `json:"updateTimeStamp"`
}

func Initialize(aEntityModel EntityModelInterface) {
	// set model (to access persistency)
	entityModel = aEntityModel

	// read configuration
	var err error
	configuration, err = entityModel.LoadConfiguration()
	if err != nil {
		log.Fatalln("Error loading configuration")
	}

	//  initialize the token cache
	identityTokenCache := IdentityTokenCacheType{}
	identityTokenCache.Cache = make(IdentityTokenCacheItemSlice, 0, 1024)
}

/*
	*******************************************************************
		Entity
	*******************************************************************
*/
func GetIdentityToken(nick, password, remoteAddr string) (IdentityTokenStruct, error) {
	identityToken := IdentityTokenStruct{}
	entity, err := entityModel.ReadByNick(nick)
	if err != nil {
		return identityToken, errors.New("nick not found")
	}
	// compare given password with saved hash of password
	err = bcrypt.CompareHashAndPassword([]byte(entity.PasswordHash), []byte(password))
	if err != nil {
		return identityToken, errors.New("invalid password")
	}

	// create identity token
	identityToken.IdentityToken = GenerateToken(16)

	// set end of validity
	minutes := configuration.IdentityTokenValidityMinutes // get number of minutes from config
	identityToken.ValidUntil = time.Now().UTC().Add(time.Minute * time.Duration(minutes))

	// generate item for auth token cache
	identityTokenCacheItem := IdentityTokenCacheItemStruct{
		Nick:          nick,
		IdentityToken: identityToken.IdentityToken,
		ValidUntil:    identityToken.ValidUntil,
		ValidFor:      remoteAddr,
	}
	identityTokenCache.Add(identityTokenCacheItem)

	return identityToken, nil
}

/*
	*******************************************************************
		Entity Token Cache
	*******************************************************************
*/
var identityTokenCache IdentityTokenCacheType

// IdentityTokenStruct describes the identity token returned to the client
type IdentityTokenStruct struct {
	IdentityToken string    `json:"identityToken"`
	ValidUntil    time.Time `json:"validUntil"`
}

// IdentityTokenCacheItemStruct describes on record of the internal list of provided identity tokens
type IdentityTokenCacheItemStruct struct {
	IdentityToken string
	Nick          string
	ValidUntil    time.Time
	ValidFor      string
}

// IdentityTokenCacheItemSlice describes the internal list of provided identity tokens
type IdentityTokenCacheItemSlice []IdentityTokenCacheItemStruct

// IdentityTokenCacheType is the actual type of the cache for identity tokens
type IdentityTokenCacheType struct {
	Cache IdentityTokenCacheItemSlice
}

// Add adds a new token to identity token cache
func (itc *IdentityTokenCacheType) Add(token IdentityTokenCacheItemStruct) {
	itc.Cache = append(itc.Cache, token)
	identityTokenCache.DeleteInvalid()
}

// DeleteInvalid deletes invalid token from identity token cache
func (itc IdentityTokenCacheType) DeleteInvalid() {

	now := time.Now().UTC()
	emptyToken := IdentityTokenCacheItemStruct{}

	// remote invalid tokens
	emptyTokenCount := 0
	for i, token := range itc.Cache {
		if token == emptyToken {
			emptyTokenCount++
			continue
		}
		if token.ValidUntil.Before(now) {
			itc.Cache[i] = emptyToken
			emptyTokenCount++
		}
	}

	// ToDo: reorganize token cache (bring empty tokens to end, reduce capacity, ...)
}

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

/*
	*******************************************************************
		Crypto functions
	*******************************************************************
*/

// Hash calculates 'hash' for 'original' using bcrypt
func Hash(original string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(original), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hash)
}

// GenerateToken generates a token
func GenerateToken(length int) string {
	chars := []rune(`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz.,-+#<>(){}[];:_#*/\!§$%&=?|@€~`)
	password := make([]rune, length)
	for i := range password {
		password[i] = chars[rand.Intn(len(chars))]
	}
	return string(password)
}

// GenerateNick generates a valid nick name
func GenerateNick() string {
	chars := []rune("123456789ABCDEFGHJKLMNPQRSTUVWXYZ")
	nick := make([]rune, 8)
	for i := range nick {
		nick[i] = chars[rand.Intn(len(chars))]
	}
	return string(nick)
}

// GeneratePassword generates a valid password
func GeneratePassword(length int) string {
	chars := []rune("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz.,-+#")
	password := make([]rune, length)
	for i := range password {
		password[i] = chars[rand.Intn(len(chars))]
	}
	return string(password)
}
