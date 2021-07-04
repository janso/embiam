package embiam

// ToDo: localization https://phrase.com/blog/posts/internationalization-i18n-go/

import (
	"errors"
	"log"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Initialize prepares embiam for usages
func Initialize(aDb DbInterface) {
	// initialize randomizer
	rand.Seed(time.Now().UTC().UnixNano())

	// initialize entity model
	Db = aDb
	Db.Initialize()

	// load configuration
	var err error
	Configuration, err = Db.LoadConfiguration()
	if err != nil {
		log.Fatalln("Error loading configuration")
	}

	// initialize based on configuration
	Db.InitializeConfiguration()

	//  initialize the token cache
	identityTokenCache := identityTokenCacheType{}
	identityTokenCache.Cache = make(identityTokenCacheItemSlice, 0, 1024)
}

// CheckIdentity checks nick and password and provides and identity token (for the remote address)
func CheckIdentity(nick, password, remoteAddr string) (identityTokenStruct, error) {
	identityToken := identityTokenStruct{}
	entity, err := Db.ReadEntityByNick(nick)
	if err != nil {
		return identityToken, errors.New("nick not found")
	}
	// check if entity is active
	if !entity.Active {
		return identityToken, errors.New("entity is not active")
	}
	// compare given password with saved hash of password
	err = bcrypt.CompareHashAndPassword([]byte(entity.PasswordHash), []byte(password))
	if err != nil {
		// wrong password
		entity.WrongPasswordCounter++
		if entity.WrongPasswordCounter > Configuration.MaxSignInAttempts {
			// deactivate entity because of multiple wrong attempts
			entity.Active = false
		}
		entity.LastSignInAttempt = time.Now().UTC()
		Db.SaveEntity(entity)
		// return error
		return identityToken, errors.New("invalid password")
	}

	// create identity token
	identityToken.Token = GenerateIdentityToken()

	// set end of validity
	seconds := Configuration.IdentityTokenValiditySeconds // get number of minutes from config
	identityToken.ValidUntil = time.Now().UTC().Add(time.Second * time.Duration(seconds))

	// save identity token, validity and remove address in cache
	identityTokenCache.add(identityToken.Token, identityToken.ValidUntil, remoteAddr)

	// return identityToken (with token and valid until)
	return identityToken, nil
}

// IsAuthValueValid checks if the identity token is valid, validFor contains information about the client, e.g. the IP address
func IsAuthValueValid(authValue string, validFor string) bool {
	/*
		authValue is transfered in the http header in field "Authorization"
		and it is determined by r.Header.Get("Authorization")
		it's value consists of the term embiam an the actual identity token,
		e.g. emibiam AvErYSeCuReIdEnTiTyToKeN
	*/
	authPart := strings.Split(authValue, " ")
	if len(authPart) < 2 {
		return false
	}
	if authPart[0] != "embiam" {
		return false
	}
	return identityTokenCache.isIdentityTokenValid(authPart[1], validFor)
}

// IsIdentityTokenValid checks if the identity token is valid, validFor contains information about the client, e.g. the IP address
func IsIdentityTokenValid(identityToken string, validFor string) bool {
	return identityTokenCache.isIdentityTokenValid(identityToken, validFor)
}

/*
	*******************************************************************
		Entity
	*******************************************************************
*/
// Entity describes a user or a device
type Entity struct {
	Nick                 string    `json:"nick"`
	PasswordHash         string    `json:"passwordHash"`
	SecretHash           string    `json:"secretHash"`
	Active               bool      `json:"active"`
	WrongPasswordCounter int       `json:"WrongPasswordCounter"`
	LastSignInAttempt    time.Time `json:"lastSignInAttempt"`
	LastSignIn           time.Time `json:"lastSignIn"`
	CreateTimeStamp      time.Time `json:"createTimeStamp"`
	UpdateTimeStamp      time.Time `json:"updateTimeStamp"`
}

// NewEntity creates a new entity
func NewEntity(entityToken string) (Entity, string, string, error) {
	// prepare new entity
	e := Entity{}

	// check entity token
	et, err := Db.ReadEntityToken(entityToken)
	if err != nil {
		return e, "", "", err
	}
	if et.ValidUntil.Before(time.Now()) {
		return e, "", "", errors.New("validity of entity token expired")
	}

	// create entity with password and secret
	password := GeneratePassword(16)
	secret := GeneratePassword(64)
	e.PasswordHash = Hash(password)
	e.SecretHash = Hash(secret)
	e.Active = true
	e.CreateTimeStamp = time.Now().UTC()

	// generate a unique nick
	for {
		e.Nick = GenerateNick()
		if !Db.EntityExists(e.Nick) {
			break
		}
	}

	// save new entity
	err = e.Save()
	if err != nil {
		return Entity{}, "", "", err
	}

	// delete entity token
	err = et.Delete()
	return e, password, secret, nil
}

// Save uses the entity model to save 'e' persistently
func (e Entity) Save() error {
	return Db.SaveEntity(&e)
}

/*
	*******************************************************************
		Entity Token
	*******************************************************************
*/
type EntityToken struct {
	Token      string
	ValidUntil time.Time
}

// NewEntityToken creates a new entity token (token itself and set validity, comming from configuration)
func NewEntityToken() EntityToken {
	// set end of validity
	hours := Configuration.EntityTokenValidityHours // number of hours the entity token is valid
	validUntil := time.Now().UTC().Add(time.Hour * time.Duration(hours))
	return EntityToken{
		Token:      GenerateEntityToken(),
		ValidUntil: validUntil,
	}
}

// Save the entity token to database
func (et EntityToken) Save() error {
	return Db.SaveEntityToken(&et)
}

// Delete the entity token from database
func (et EntityToken) Delete() error {
	return Db.DeleteEntityToken(et.Token)
}

/*
	*******************************************************************
		Identity Token Cache
	*******************************************************************
*/
var identityTokenCache identityTokenCacheType

// identityTokenCacheItemStruct describes on record of the internal list of provided identity tokens
type identityTokenCacheItemStruct struct {
	Token      string
	ValidUntil time.Time
	ValidFor   string
}

// identityTokenCacheItemSlice describes the internal list of provided identity tokens
type identityTokenCacheItemSlice []identityTokenCacheItemStruct

// identityTokenCacheType is the actual type of the cache for identity tokens
type identityTokenCacheType struct {
	Cache identityTokenCacheItemSlice
}

type identityTokenStruct struct {
	Token      string
	ValidUntil time.Time
}

// add adds a new token to identity token cache
func (itc *identityTokenCacheType) add(token string, validUntil time.Time, validFor string) {
	now := time.Now().UTC()
	emptyIdentityToken := identityTokenCacheItemStruct{}
	newIdentityToken := identityTokenCacheItemStruct{
		Token:      token,
		ValidUntil: validUntil,
		ValidFor:   validFor,
	}
	placed := false

	for i, token := range identityTokenCache.Cache {
		// invalidate token that ran out of validity (by setting it empty)
		if token.ValidUntil.Before(now) {
			identityTokenCache.Cache[i] = emptyIdentityToken
		}
		// put new token at first empty position
		if !placed && token == emptyIdentityToken {
			identityTokenCache.Cache[i] = newIdentityToken
			placed = true
		}
	}

	if !placed {
		itc.Cache = append(itc.Cache, newIdentityToken)
	}
}

// isIdentityTokenValid checks if an identity token is valid
func (itc identityTokenCacheType) isIdentityTokenValid(identityToken string, validFor string) bool {
	now := time.Now().UTC()
	emptyToken := identityTokenCacheItemStruct{}

	for i, token := range identityTokenCache.Cache {
		if token == emptyToken {
			continue
		}
		// invalidate token that ran out of validity (by setting it empty)
		if token.ValidUntil.Before(now) {
			identityTokenCache.Cache[i] = emptyToken
			continue
		}
		// check identity token
		if itc.Cache[i].Token == identityToken {
			// check if client's address is correct
			if identityTokenCache.Cache[i].ValidFor == validFor {
				return true
			}
		}
	}

	return false
}

/*
	*******************************************************************
		Crypto functions
	*******************************************************************
*/
var tokenChars = []byte(`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz.,-+#(){}[];:_#*!$%&=?|@~`)
var nickChars = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZ")
var passwordChars = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz.,-+#")

// Hash calculates 'hash' for 'original' using bcrypt
func Hash(original string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(original), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hash)
}

// GenerateIdentityToken generates a identity token
func GenerateIdentityToken() string {
	const tokenLength = 24
	password := make([]byte, tokenLength)
	for i := range password {
		password[i] = tokenChars[rand.Intn(len(tokenChars))]
	}
	return string(password)
}

// GenerateNick generates a nick
func GenerateNick() string {
	const nickLength = 8
	nick := make([]byte, nickLength)
	for i := range nick {
		nick[i] = nickChars[rand.Intn(len(nickChars))]
	}
	return string(nick)
}

// GeneratePassword generates a password
func GeneratePassword(length int) string {
	password := make([]byte, length)
	for i := range password {
		password[i] = passwordChars[rand.Intn(len(passwordChars))]
	}
	return string(password)
}

// GenerateEntityToken generates a valid entity token
func GenerateEntityToken() string {
	const tokenLength = 32
	token := make([]byte, tokenLength)
	for i := range token {
		token[i] = nickChars[rand.Intn(len(nickChars))]
	}
	return string(token)
}
