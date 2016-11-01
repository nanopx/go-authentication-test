package services

import (
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
	"github.com/nanopx/go-authentication-test/services/models"
	"github.com/nanopx/go-authentication-test/services/authentication"
	"encoding/json"
)

func Login(requestUser *models.User) (int, []byte) {
	authentication := authentication.InitJWTAuthentication()

	if authentication.Authenticate(requestUser) {
		token, err := authentication.GenerateToken(requestUser.UUID)
		if err != nil {
			return http.StatusInternalServerError, []byte("")
		} else {
			//response, _ := json.Marshal(parameters.TokenAuthentication{token})
			//return http.StatusOK, response
		}
	}
}

func RefreshToken(requestUser *models.User) []byte {
	authentication := authentication.InitJWTAuthentication()
	token, err := authentication.GenerateToken(requestUser.UUID)
	if err != nil {
		panic(err)
	}
	//response, err := json.Marshal(parameters.TokenAuthentication{token})
	//if err != nil {
	//	panic(err)
	//}
	//return response
}

func Logout(req *http.Request) error {
	authentication := authentication.InitJWTAuthentication()
	tokenRequest, err := jwt.Parse(req, func(token *jwt.Token) (interface{}, error) {
		return authentication.PublicKey, nil
	})
	if err != nil {
		return err
	}
	tokenString := req.Header.Get("Authorization")
	return authentication.Logout(tokenString, tokenRequest)
}