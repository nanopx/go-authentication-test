package authentication

import (
	jwt "github.com/dgrijalva/jwt-go"
	"crypto/rsa"
	"github.com/nanopx/go-authentication-test/services/models"
	"time"
	"golang.org/x/crypto/bcrypt"
	"github.com/pborman/uuid"
)

type JWTAuthentication struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

const (
	tokenDuration = 72
	expireOffset  = 3600
)

var jwtAuthenticationInstance *JWTAuthentication = nil

func InitJWTAuthentication() *JWTAuthentication {
	if jwtAuthenticationInstance == nil {
		jwtAuthenticationInstance = &JWTAuthentication{
			privateKey: getPrivateKey(),
			PublicKey: getPublicKey(),
		}
	}

	return jwtAuthenticationInstance
}

func (auth *JWTAuthentication) GenerateToken(userUUID string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS512)
	//token.Claims["exp"] = time.Now().Add(time.Hour * time.Duration(settings.Get().JWTExpirationDelta)).Unix()
	token.Claims["iat"] = time.Now().Unix()
	token.Claims["sub"] = userUUID
	tokenString, err := token.SignedString(auth.privateKey)
	if err != nil {
		panic(err)
		return "", err
	}
	return tokenString, nil
}

func (auth *JWTAuthentication) Authenticate(user *models.User) bool {
	// TODO: edit this test code

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testing"), 10)

	testUser := models.User{
		UUID:     uuid.New(),
		Username: "haku",
		Password: string(hashedPassword),
	}

	return user.Username == testUser.Username && bcrypt.CompareHashAndPassword([]byte(testUser.Password), []byte(user.Password)) == nil
}


func (auth *JWTAuthentication) getTokenRemainingValidity(timestamp interface{}) int {
	if validity, ok := timestamp.(float64); ok {
		tm := time.Unix(int64(validity), 0)
		remaining := tm.Sub(time.Now())
		if remaining > 0 {
			return int(remaining.Seconds() + expireOffset)
		}
	}
	return expireOffset
}

func (auth *JWTAuthentication) Logout(tokenString string, token *jwt.Token) error {
	//redisConn := redis.Connect()
	//return redisConn.SetValue(tokenString, tokenString, auth.getTokenRemainingValidity(token.Claims["exp"]))
}

func (auth *JWTAuthentication) IsInBlacklist(token string) bool {
	//redisConn := redis.Connect()
	//redisToken, _ := redisConn.GetValue(token)
	//
	//if redisToken == nil {
	//	return false
	//}
	//
	//return true
}

func getPrivateKey() *rsa.PrivateKey {
	//privateKeyFile, err := os.Open(settings.Get().PrivateKeyPath)
	//if err != nil {
	//	panic(err)
	//}
	//
	//pemfileinfo, _ := privateKeyFile.Stat()
	//var size int64 = pemfileinfo.Size()
	//pembytes := make([]byte, size)
	//
	//buffer := bufio.NewReader(privateKeyFile)
	//_, err = buffer.Read(pembytes)
	//
	//data, _ := pem.Decode([]byte(pembytes))
	//
	//privateKeyFile.Close()
	//
	//privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	//
	//if err != nil {
	//	panic(err)
	//}
	//
	//return privateKeyImported
}

func getPublicKey() *rsa.PublicKey {
	//publicKeyFile, err := os.Open(settings.Get().PublicKeyPath)
	//if err != nil {
	//	panic(err)
	//}
	//
	//pemfileinfo, _ := publicKeyFile.Stat()
	//var size int64 = pemfileinfo.Size()
	//pembytes := make([]byte, size)
	//
	//buffer := bufio.NewReader(publicKeyFile)
	//_, err = buffer.Read(pembytes)
	//
	//data, _ := pem.Decode([]byte(pembytes))
	//
	//publicKeyFile.Close()
	//
	//publicKeyImported, err := x509.ParsePKIXPublicKey(data.Bytes)
	//
	//if err != nil {
	//	panic(err)
	//}
	//
	//rsaPub, ok := publicKeyImported.(*rsa.PublicKey)
	//
	//if !ok {
	//	panic(err)
	//}
	//
	//return rsaPub
}
