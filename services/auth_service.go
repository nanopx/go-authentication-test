package services

import (
	jwt "github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"net/http"
	"github.com/nanopx/go-authentication-test/services/models"
	"github.com/nanopx/go-authentication-test/services/authentication"
	"encoding/json"
)

type TokenAuthentication struct {
	Token string `json:"token" form:"token"`
}

func Login(requestUser *models.User) (int, []byte) {
	authentication := authentication.InitJWTAuthentication()

	if authentication.Authenticate(requestUser) {
		token, err := authentication.GenerateToken(requestUser.UUID)
		if err != nil {
			return http.StatusInternalServerError, []byte("")
		} else {
			response, _ := json.Marshal(TokenAuthentication{token})
			return http.StatusOK, response
		}
	}

	return http.StatusUnauthorized, []byte("")
}

func RefreshToken(requestUser *models.User) []byte {
	authentication := authentication.InitJWTAuthentication()
	token, err := authentication.GenerateToken(requestUser.UUID)
	if err != nil {
		panic(err)
	}
	res, err := json.Marshal(TokenAuthentication{token})
	if err != nil {
		panic(err)
	}
	return res
}

func Logout(req *http.Request) error {
	authentication := authentication.InitJWTAuthentication()

	tokenRequest, err := jwtRequest.ParseFromRequest(req, jwtRequest.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return authentication.PublicKey, nil
	})
	if err != nil {
		return err
	}
	tokenString := req.Header.Get("Authorization")
	return authentication.Logout(tokenString, tokenRequest)
}