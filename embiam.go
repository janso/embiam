package embiam

// ToDo: localization https://phrase.com/blog/posts/internationalization-i18n-go/

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
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
}

// CheckAuthIdentity checks nick and password and provides and identity token (for validFor)
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
	nickpass := strings.Split(string(decodedCredentials), ":")
	if len(nickpass) < 2 {
		return identityTokenStruct{}, "", errorInvalidAuthorization
	}
	// do actual check
	identityToken, err := CheckIdentity(nickpass[0], nickpass[1], validFor)
	return identityToken, nickpass[0], err
}

// CheckIdentity checks nick and password and provides and identity token (for validFor)
func CheckIdentity(nick, password, validFor string) (identityTokenStruct, error) {
	identityToken := identityTokenStruct{}
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
			log.Printf("ERROR saving nick %s after wrong password\n", nick)
		}
		// return error
		return identityToken, errors.New("invalid password")
	}
	// save successful sign in
	entity.LastSignIn = time.Now().UTC()
	err = Db.SaveEntity(entity)
	if err != nil {
		log.Printf("ERROR saving nick %s after sign in\n", nick)
	}

	// create identity token
	identityToken.Token = GenerateIdentityToken()

	// set end of validity
	seconds := Configuration.IdentityTokenValiditySeconds // get number of minutes from config
	identityToken.ValidUntil = time.Now().UTC().Add(time.Second * time.Duration(seconds))

	// save identity token, validity and remove address in cache
	identityTokenCache.add(identityToken.Token, identityToken.ValidUntil, validFor)

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

// PublicEntity describes a user or a device (without hashes)
type PublicEntity struct {
	Nick                 string    `json:"nick"`
	Active               bool      `json:"active"`
	WrongPasswordCounter int       `json:"WrongPasswordCounter"`
	LastSignInAttempt    time.Time `json:"lastSignInAttempt"`
	LastSignIn           time.Time `json:"lastSignIn"`
	CreateTimeStamp      time.Time `json:"createTimeStamp"`
	UpdateTimeStamp      time.Time `json:"updateTimeStamp"`
}

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

// NewEntity contains all fields of Entity but also the password and the secret (not only the hash)
type NewEntityStruct struct {
	Nick                 string    `json:"nick"`
	Password             string    `json:"password"`
	Secret               string    `json:"secret"`
	PasswordHash         string    `json:"passwordHash"`
	SecretHash           string    `json:"secretHash"`
	Active               bool      `json:"active"`
	WrongPasswordCounter int       `json:"WrongPasswordCounter"`
	LastSignInAttempt    time.Time `json:"lastSignInAttempt"`
	LastSignIn           time.Time `json:"lastSignIn"`
	CreateTimeStamp      time.Time `json:"createTimeStamp"`
	UpdateTimeStamp      time.Time `json:"updateTimeStamp"`
}

// NewEntity creates a new entity using an entityToken and PIN
func NewEntity(entityToken, pin string) (newEntity NewEntityStruct, err error) {
	// prepare new entity
	ne := NewEntityStruct{}

	// check entity token
	et, err := Db.ReadEntityToken(entityToken)
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
	ne.Password = GeneratePassword(32)
	ne.Secret = GeneratePassword(64)
	ne.PasswordHash = Hash(ne.Password)
	ne.SecretHash = Hash(ne.Secret)
	ne.Active = true
	ne.CreateTimeStamp = time.Now().UTC()

	// generate a unique nick
	for {
		ne.Nick = GenerateNick()
		if !Db.EntityExists(ne.Nick) {
			break
		}
	}

	// save new entity
	e := ne.ToEntity()
	err = Db.SaveEntity(&e)
	if err != nil {
		return NewEntityStruct{}, err
	}

	// delete entity token
	err = et.Delete()
	if err != nil {
		return NewEntityStruct{}, err
	}

	return ne, nil
}

// ToPublicEntity converts an EntityStruct to PublicEntity
func (e *Entity) ToPublicEntity() PublicEntity {
	return PublicEntity{
		Nick:                 e.Nick,
		Active:               e.Active,
		WrongPasswordCounter: e.WrongPasswordCounter,
		LastSignInAttempt:    e.LastSignInAttempt,
		LastSignIn:           e.LastSignIn,
		CreateTimeStamp:      e.CreateTimeStamp,
		UpdateTimeStamp:      e.UpdateTimeStamp,
	}
}

// ToEntity converts a NewEntityStruct to Entity
func (ne *NewEntityStruct) ToEntity() Entity {
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
func NewEntityToken() EntityToken {
	// set end of validity
	hours := Configuration.EntityTokenValidityHours // number of hours the entity token is valid
	validUntil := time.Now().UTC().Add(time.Hour * time.Duration(hours))
	return EntityToken{
		Token:      GenerateEntityToken(),
		Pin:        GeneratePin(),
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

/********************************************************************
	IDENTITY TOKEN CACHE
	An identity token is provides after authentication with
	nick and password. For the subsequent actions (e.g. API calls)
	the client (API consumer) is only using the identity token
	instead of the credentials (nick and password).
	So an identity token completely different than the entity token.
********************************************************************/
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

// identityTokenStruct is the type for the identity token send to the client, containing the actual token and validUntil
type identityTokenStruct struct {
	Token      string    `json:"token"`
	ValidUntil time.Time `json:"validUntil"`
}

// add a new token to the identity token cache
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
func (itc identityTokenCacheType) isIdentityTokenValid(tokenToTest string, validFor string) bool {
	if len(tokenToTest) == 0 {
		return false
	}

	now := time.Now().UTC()
	emptyIdentityToken := identityTokenCacheItemStruct{}

	for i, identityTokenFromCache := range identityTokenCache.Cache {
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

// GeneratePin generates a PIN
func GeneratePin() string {
	const pinLength = 6
	pin := make([]byte, pinLength)
	for i := range pin {
		pin[i] = nickChars[rand.Intn(len(nickChars))]
	}
	return string(pin)
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
