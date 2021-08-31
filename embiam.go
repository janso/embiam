package embiam

// ToDo: localization https://phrase.com/blog/posts/internationalization-i18n-go/

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var Configuration ConfigurationStruct

type ConfigurationStruct struct {
	ServerId                     string `json:"serverId"`
	Port                         string `json:"port"`
	EntityTokenValidityHours     int    `json:"entityTokenValidityHours"`
	IdentityTokenValiditySeconds int    `json:"identityTokenValiditySeconds"`
	MaxSignInAttempts            int    `json:"maxSignInAttempts"`
}

// Initialize prepares embiam
func Initialize(aDb DbInterface) {
	// initialize randomizer
	rand.Seed(time.Now().UTC().UnixNano())

	// set default configuration
	sid := ServerId{}
	sid.New()
	Configuration = ConfigurationStruct{
		ServerId:                     sid.String(),
		Port:                         "8242",
		EntityTokenValidityHours:     168,
		IdentityTokenValiditySeconds: 720,
		MaxSignInAttempts:            5,
	}

	// initialize entity model
	Db = aDb
	Db.Initialize()

	//  initialize the token cache
	identityTokenCache := identityTokenCacheType{}
	identityTokenCache.Cache = make(identityTokenCacheItemSlice, 0, 1024)

	// initialize authorizations
	initializeAuthorizations()
}

// CheckAuthIdentity checks an authValue and provides and identity token (for validFor)
// it also returns the nick, that was checked
func CheckAuthIdentity(authValue string, validFor string) (identityTokenStruct, string, error) {
	/*
		authValue is transfered in the http header in field "Authorization"
		and it is determined by r.Header.Get("Authorization")
		it's value consists of the term embiam an the nick and password,
		separated by colon and base64-encoded. Like in simple authentication
	*/
	errorInvalidAuthorization := errors.New("invalid authorization")
	authPart := strings.Split(authValue, " ")
	if len(authPart) < 2 {
		return identityTokenStruct{}, "", errorInvalidAuthorization
	}
	if authPart[0] != "embiam" {
		return identityTokenStruct{}, "", errorInvalidAuthorization
	}
	// base64 decode
	decodedCredentials, err := base64.StdEncoding.DecodeString(authPart[1])
	if err != nil {
		return identityTokenStruct{}, "", errorInvalidAuthorization
	}
	// split username and password
	splitResult := strings.Split(string(decodedCredentials), ":")
	if len(splitResult) < 2 {
		return identityTokenStruct{}, "", errorInvalidAuthorization
	}
	// do actual check
	identityToken, err := CheckIdentity(splitResult[0], splitResult[1], validFor)
	// return identity token, nick and error
	return identityToken, splitResult[0], err
}

// CheckIdentity checks nick and password and provides and identity token (for validFor)
func CheckIdentity(nick, password, validFor string) (identityTokenStruct, error) {
	identityToken := identityTokenStruct{}
	// read complete entity by nick
	entity, err := Db.ReadEntityByNick(nick)
	if err != nil {
		return identityToken, err
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
		// save failed signin
		entity.LastSignInAttempt = time.Now().UTC()
		err = Db.SaveEntity(entity)
		if err != nil {
			return identityToken, err
		}
		// return error
		return identityToken, errors.New("invalid password")
	}
	// save successful sign in
	entity.LastSignIn = time.Now().UTC()
	err = Db.SaveEntity(entity)
	if err != nil {
		return identityToken, err
	}

	// create identity token
	identityToken.Token = generateIdentityToken()

	// set end of validity
	seconds := Configuration.IdentityTokenValiditySeconds // get number of minutes from config
	identityToken.ValidUntil = time.Now().UTC().Add(time.Second * time.Duration(seconds))

	// add identity token to cache
	identityTokenCache.add(identityToken.Token, identityToken.ValidUntil, validFor, nick)

	// prepare authorizations for nick
	err = AddNicksAuthorizationsToCache(entity)
	if err != nil {
		return identityToken, err
	}

	// return identityToken (with token and valid until)
	return identityToken, nil
}

// IsAuthIdentityTokenValid checks if the identity token is valid, validFor contains information about the client, e.g. the IP address
func IsAuthIdentityTokenValid(authValue string, validFor string) bool {
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
	// base64 decode
	decodedToken, err := base64.StdEncoding.DecodeString(authPart[1])
	if err != nil {
		return false
	}
	return identityTokenCache.isIdentityTokenValid(string(decodedToken), validFor)
}

// IsIdentityTokenValid checks if the identity token is valid, validFor contains information about the client, e.g. the IP address
func IsIdentityTokenValid(token string, validFor string) bool {
	return identityTokenCache.isIdentityTokenValid(token, validFor)
}

/********************************************************************
	ENTITY

	The entity describes a person or device that needs
	authentication (and authorization). The entity is identified
	by the so called 'nick', which is similar to a username.
	The entity also contains the hash of the password and hash
	of the secret. The secret is a second, more complex,
	password and it is used to chance the password or to
	unlock the entity, after it was disabled, e.g. after
	multiple unsuccessful password entries.
*********************************************************************/

type (
	// Entity describes a user or a device
	Entity struct {
		Nick                 string       `json:"nick"`
		PasswordHash         string       `json:"passwordHash"`
		SecretHash           string       `json:"secretHash"`
		Active               bool         `json:"active"`
		WrongPasswordCounter int          `json:"wrongPasswordCounter"`
		LastSignInAttempt    time.Time    `json:"lastSignInAttempt"`
		LastSignIn           time.Time    `json:"lastSignIn"`
		CreateTimeStamp      time.Time    `json:"createTimeStamp"`
		UpdateTimeStamp      time.Time    `json:"updateTimeStamp"`
		Roles                []RoleIdType `json:"roles"`
	}

	// PublicEntity describes a user or a device (without hashes)
	PublicEntity struct {
		Nick                 string       `json:"nick"`
		Active               bool         `json:"active"`
		WrongPasswordCounter int          `json:"wrongPasswordCounter"`
		LastSignInAttempt    time.Time    `json:"lastSignInAttempt"`
		LastSignIn           time.Time    `json:"lastSignIn"`
		CreateTimeStamp      time.Time    `json:"createTimeStamp"`
		UpdateTimeStamp      time.Time    `json:"updateTimeStamp"`
		Roles                []RoleIdType `json:"roles"`
	}

	// NewEntity contains all fields of Entity but also the password and the secret (not only the hash)
	NewEntityStruct struct {
		Nick                 string       `json:"nick"`
		Password             string       `json:"password"`
		Secret               string       `json:"secret"`
		PasswordHash         string       `json:"passwordHash"`
		SecretHash           string       `json:"secretHash"`
		Active               bool         `json:"active"`
		WrongPasswordCounter int          `json:"wrongPasswordCounter"`
		LastSignInAttempt    time.Time    `json:"lastSignInAttempt"`
		LastSignIn           time.Time    `json:"lastSignIn"`
		CreateTimeStamp      time.Time    `json:"createTimeStamp"`
		UpdateTimeStamp      time.Time    `json:"updateTimeStamp"`
		Roles                []RoleIdType `json:"roles"`
	}
)

// NewEntity creates a new entity using an entityToken and PIN
func NewEntity(entityToken, pin string) (newEntity NewEntityStruct, err error) {
	// prepare new entity
	ne := NewEntityStruct{}

	// check entity token
	et, err := Db.readEntityToken(entityToken)
	if err != nil {
		return ne, err
	}
	// check validity
	if et.ValidUntil.Before(time.Now()) {
		return ne, errors.New("validity of entity token expired")
	}
	// check pin
	if et.Pin != pin {
		return ne, errors.New("invalid PIN")
	}

	// create entity with password and secret
	ne.Password = generatePassword(32)
	ne.Secret = generatePassword(64)
	ne.PasswordHash = Hash(ne.Password)
	ne.SecretHash = Hash(ne.Secret)
	ne.Active = true
	ne.CreateTimeStamp = time.Now().UTC()

	// generate a unique nick
	for {
		ne.Nick = generateNick()
		if !Db.EntityExists(ne.Nick) {
			break
		}
	}

	// assign default roles
	ne.Roles = defaultRoles

	// save new entity
	e := ne.toEntity()
	err = Db.SaveEntity(&e)
	if err != nil {
		return NewEntityStruct{}, err
	}

	// delete entity token
	err = Db.deleteEntityToken(et.Token)
	if err != nil {
		return NewEntityStruct{}, err
	}

	return ne, nil
}

// toPublicEntity converts an EntityStruct to PublicEntity
func (e *Entity) toPublicEntity() PublicEntity {
	return PublicEntity{
		Nick:                 e.Nick,
		Active:               e.Active,
		WrongPasswordCounter: e.WrongPasswordCounter,
		LastSignInAttempt:    e.LastSignInAttempt,
		LastSignIn:           e.LastSignIn,
		CreateTimeStamp:      e.CreateTimeStamp,
		UpdateTimeStamp:      e.UpdateTimeStamp,
		Roles:                e.Roles,
	}
}

// toEntity converts a NewEntityStruct to Entity
func (ne *NewEntityStruct) toEntity() Entity {
	return Entity{
		Nick:                 ne.Nick,
		PasswordHash:         ne.PasswordHash,
		SecretHash:           ne.SecretHash,
		Active:               ne.Active,
		WrongPasswordCounter: ne.WrongPasswordCounter,
		LastSignInAttempt:    ne.LastSignInAttempt,
		LastSignIn:           ne.LastSignIn,
		CreateTimeStamp:      ne.CreateTimeStamp,
		UpdateTimeStamp:      ne.UpdateTimeStamp,
		Roles:                ne.Roles,
	}
}

/********************************************************************
	ENTITY TOKEN

	Entity Tokens are used to create new entities. The administrator
	creates an entity token and sends it to the new user. The new
	user uses the entity token to create an new entity. After the
	entity was created, the entity token is deleted.
********************************************************************/
type EntityToken struct {
	Token      string    `json:"token"`
	Pin        string    `json:"pin"`
	ValidUntil time.Time `json:"validUntil"`
}

// NewEntityToken creates a new entity token (token itself and validity, comming from configuration)
func NewEntityToken() (EntityToken, error) {
	// set end of validity
	hours := Configuration.EntityTokenValidityHours // number of hours the entity token is valid
	validUntil := time.Now().UTC().Add(time.Hour * time.Duration(hours))
	et := EntityToken{
		Token:      generateEntityToken(),
		Pin:        generatePin(),
		ValidUntil: validUntil,
	}
	err := Db.saveEntityToken(&et)
	return et, err
}

/********************************************************************
	IDENTITY TOKEN CACHE
	An identity token is provides after authentication with
	nick and password. For the subsequent actions (e.g. API calls)
	the client (API consumer) is only using the identity token
	instead of the credentials (nick and password).
	So an identity token completely different than the entity token.
********************************************************************/

// identityTokenCacheItemStruct describes on record of the internal list of provided identity tokens
type (
	identityTokenCacheItemStruct struct {
		Token      string
		ValidUntil time.Time
		ValidFor   string // identification of the caller, e.g. the IP
		Nick       string
	}

	// identityTokenCacheItemSlice describes the internal list of provided identity tokens
	identityTokenCacheItemSlice []identityTokenCacheItemStruct

	// identityTokenCacheType is the actual type of the cache for identity tokens
	identityTokenCacheType struct {
		Cache identityTokenCacheItemSlice
	}

	// identityTokenStruct is the type for the identity token send to the client, containing the actual token and validUntil
	identityTokenStruct struct {
		Token      string    `json:"token"`
		ValidUntil time.Time `json:"validUntil"`
	}
)

var identityTokenCache identityTokenCacheType

// add a new token to the identity token cache
func (itc *identityTokenCacheType) add(token string, validUntil time.Time, validFor, nick string) {
	now := time.Now().UTC()
	emptyIdentityToken := identityTokenCacheItemStruct{}
	newIdentityToken := identityTokenCacheItemStruct{
		Token:      token,
		ValidUntil: validUntil,
		ValidFor:   validFor,
		Nick:       nick,
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
func (itc identityTokenCacheType) isIdentityTokenValid(tokenToTest string, validFor string) bool {
	if len(tokenToTest) == 0 {
		return false
	}

	now := time.Now().UTC()
	emptyIdentityToken := identityTokenCacheItemStruct{}

	// ToDo: Change identityTokenCacheType from slice to map??
	for i, identityTokenFromCache := range identityTokenCache.Cache {
		// ToDo: Change identityTokenCache to itc
		if identityTokenFromCache == emptyIdentityToken {
			continue
		}
		// invalidate token that ran out of validity (by setting it empty)
		if identityTokenFromCache.ValidUntil.Before(now) {
			identityTokenCache.Cache[i] = emptyIdentityToken
			continue
		}
		// check if tokens are equal
		if identityTokenCache.Cache[i].Token == tokenToTest {
			// check if client's address is correct
			if identityTokenFromCache.ValidFor == validFor {
				return true
			}
		}
	}
	return false
}

// getNick returns the nick for an identity token
func (itc identityTokenCacheType) getNick(token string) (nick string) {
	// ToDo: Switch itc.Cache to map??
	for i := range itc.Cache {
		// check if tokens are equal
		if identityTokenCache.Cache[i].Token == token {
			nick = identityTokenCache.Cache[i].Nick
			return nick
		}
	}
	return ""
}

/********************************************************************
	Crypto functions and generators
********************************************************************/
var tokenChars = []byte(`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz.,-+#(){}[];:_#*!$%=?|@~`)
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

// generateIdentityToken generates a identity token
func generateIdentityToken() string {
	const tokenLength = 24
	password := make([]byte, tokenLength)
	for i := range password {
		password[i] = tokenChars[rand.Intn(len(tokenChars))]
	}
	return string(password)
}

// generateNick generates a nick
func generateNick() string {
	const nickLength = 8
	nick := make([]byte, nickLength)
	for i := range nick {
		nick[i] = nickChars[rand.Intn(len(nickChars))]
	}
	return string(nick)
}

// generatePin generates a PIN
func generatePin() string {
	const pinLength = 6
	pin := make([]byte, pinLength)
	for i := range pin {
		pin[i] = nickChars[rand.Intn(len(nickChars))]
	}
	return string(pin)
}

// generatePassword generates a password
func generatePassword(length int) string {
	password := make([]byte, length)
	for i := range password {
		password[i] = passwordChars[rand.Intn(len(passwordChars))]
	}
	return string(password)
}

// generateEntityToken generates a valid entity token
func generateEntityToken() string {
	const tokenLength = 32
	token := make([]byte, tokenLength)
	for i := range token {
		token[i] = nickChars[rand.Intn(len(nickChars))]
	}
	return string(token)
}

// random 128-bit Id of the server
type ServerId [2]uint64

// New generates a new ServerId
func (id *ServerId) New() {
	id[0] = rand.Uint64()
	id[1] = rand.Uint64()
}

// Stringer for ServerId
func (id *ServerId) String() string {
	a := id[0] & 0xffff
	b := id[0] >> 16 & 0xffff
	c := id[0] >> 32 & 0xffff
	d := id[0] >> 48 & 0xffff
	e := id[1] & 0xffff
	f := id[1] >> 16 & 0xffff
	g := id[1] >> 32 & 0xffff
	h := id[1] >> 48 & 0xffff
	return fmt.Sprintf("%04x.%04x.%04x.%04x-%04x.%04x.%04x.%04x", h, g, f, e, d, c, b, a)
}
