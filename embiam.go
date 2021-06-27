package embiam

import (
	"errors"
	"log"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Initialize prepares embiam for usages
func Initialize(aEntityModel EntityModelInterface) {
	// set model (to access persistency)
	entityModel = aEntityModel

	// read configuration
	var err error
	Configuration, err = entityModel.LoadConfiguration()
	if err != nil {
		log.Fatalln("Error loading configuration")
	}

	//  initialize the token cache
	identityTokenCache := identityTokenCacheType{}
	identityTokenCache.Cache = make(identityTokenCacheItemSlice, 0, 1024)

	// initialize randomizer
	rand.Seed(time.Now().UTC().UnixNano())
}

// GetIdentityToken checks nick and password and provides and identity token (for the remote address)
func GetIdentityToken(nick, password, remoteAddr string) (identityTokenStruct, error) {
	identityToken := identityTokenStruct{}
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
	seconds := Configuration.IdentityTokenValiditySeconds // get number of minutes from config
	identityToken.ValidUntil = time.Now().UTC().Add(time.Second * time.Duration(seconds))

	// save identity token, validity and remove address in cache
	identityTokenCache.add(identityToken.IdentityToken, identityToken.ValidUntil, remoteAddr)

	// return identityToken (with token and valid until)
	return identityToken, nil
}

// IsIdentityTokenValid check if the identity token is valid for validUntil and validFor
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
	LastSingIn           time.Time `json:"lastSingIn"`
	WrongPasswordCounter int       `json:"WrongPasswordCounter"`
	CreateTimeStamp      time.Time `json:"createTimeStamp"`
	UpdateTimeStamp      time.Time `json:"updateTimeStamp"`
}

// Save uses the entity model to save 'e' persistently
func (e Entity) Save() error {
	return entityModel.Save(&e)
}

// NewEntity creates a new entity
func NewEntity() Entity {
	// create entity with password and secret
	e := Entity{
		Nick:                 "",
		PasswordHash:         "",
		SecretHash:           "",
		Active:               false,
		LastSingIn:           time.Time{},
		WrongPasswordCounter: 0,
		CreateTimeStamp:      time.Now(),
		UpdateTimeStamp:      time.Time{},
	}

	// generate a unique nick
	for {
		e.Nick = GenerateNick()
		if !entityModel.NickExists(e.Nick) {
			break
		}
	}
	return e
}

/*
	*******************************************************************
		Entity Token Cache
	*******************************************************************
*/
var identityTokenCache identityTokenCacheType

// identityTokenStruct describes the identity token returned to the client
type identityTokenStruct struct {
	IdentityToken string    `json:"identityToken"`
	ValidUntil    time.Time `json:"validUntil"`
}

// identityTokenCacheItemStruct describes on record of the internal list of provided identity tokens
type identityTokenCacheItemStruct struct {
	IdentityToken string
	ValidUntil    time.Time
	ValidFor      string
}

// identityTokenCacheItemSlice describes the internal list of provided identity tokens
type identityTokenCacheItemSlice []identityTokenCacheItemStruct

// identityTokenCacheType is the actual type of the cache for identity tokens
type identityTokenCacheType struct {
	Cache identityTokenCacheItemSlice
}

// add adds a new token to identity token cache
func (itc *identityTokenCacheType) add(token string, validUntil time.Time, validFor string) {
	now := time.Now().UTC()
	emptyIdentityToken := identityTokenCacheItemStruct{}
	newIdentityToken := identityTokenCacheItemStruct{
		IdentityToken: token,
		ValidUntil:    validUntil,
		ValidFor:      validFor,
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
		if itc.Cache[i].IdentityToken == identityToken {
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
