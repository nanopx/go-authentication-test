package authentication

import (
	jwt "github.com/dgrijalva/jwt-go"
	"crypto/rsa"
	"github.com/nanopx/go-authentication-test/services/models"
	"time"
	//"golang.org/x/crypto/bcrypt"
	//"github.com/pborman/uuid"
	"os"
	"bufio"
	"encoding/pem"
	"crypto/x509"
	"github.com/nanopx/go-authentication-test/config"
)

type JWTAuthentication struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

//type Claims struct {
//	exp int64
//	iat int64
//	sub string
//}

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

func (auth *JWTAuthentication) GenerateToken(userId string) (string, error) {

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(config.Get().JWTExpirationHours)).Unix(),
		IssuedAt: time.Now().Unix(),
		Subject: userId,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	ss, err := token.SignedString(auth.privateKey)
	if err != nil {
		panic(err)
		return "", err
	}
	return ss, nil
}

func (auth *JWTAuthentication) Authenticate(user *models.User) bool {
	//hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testing"), 10)
	//
	//testUser := models.User{
	//	UUID:     uuid.New(),
	//	Username: "test",
	//	Password: string(hashedPassword),
	//}

	//return user.Username == testUser.Username && bcrypt.CompareHashAndPassword([]byte(testUser.Password), []byte(user.Password)) == nil
	return true
}


func (auth *JWTAuthentication) getTokenRemainingExpirationTime(timestamp interface{}) int {
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
	return nil
}

func (auth *JWTAuthentication) IsInBlacklist(token string) bool {
	//redisConn := redis.Connect()
	//redisToken, _ := redisConn.GetValue(token)
	//
	//if redisToken == nil {
	return false
	//}
	//
	//return true
}

func getPrivateKey() *rsa.PrivateKey {
	privateKeyFile, err := os.Open(config.Get().PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	pemfile, _ := privateKeyFile.Stat()
	var size int64 = pemfile.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	return privateKeyImported
}

func getPublicKey() *rsa.PublicKey {
	publicKeyFile, err := os.Open(config.Get().PublicKeyPath)
	if err != nil {
		panic(err)
	}

	pemfile, _ := publicKeyFile.Stat()
	var size int64 = pemfile.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	publicKeyFile.Close()

	publicKeyImported, err := x509.ParsePKIXPublicKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	rsaPub, ok := publicKeyImported.(*rsa.PublicKey)

	if !ok {
		panic(err)
	}

	return rsaPub
}
