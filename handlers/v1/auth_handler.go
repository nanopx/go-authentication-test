package v1

import (
	"net/http"
	"github.com/nanopx/go-authentication-test/services/models"
	"encoding/json"
	"github.com/nanopx/go-authentication-test/services"
	"fmt"
	"github.com/nanopx/go-authentication-test/services/authentication"
	jwt "github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
)

func Login(res http.ResponseWriter, req *http.Request) {
	requestUser := new(models.User)
	//decoder := json.NewDecoder(req.Body)
	//decoder.Decode(&requestUser)

	responseStatus, token := services.Login(requestUser)

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(responseStatus)
	res.Write(token)
}

func RefreshToken(res http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	requestUser := new(models.User)
	decoder := json.NewDecoder(req.Body)
	decoder.Decode(&requestUser)

	res.Header().Set("Content-Type", "application/json")
	res.Write(services.RefreshToken(requestUser))
}

func Logout(res http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	err := services.Logout(req)

	res.Header().Set("Content-Type", "application/json")
	if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
	} else {
		res.WriteHeader(http.StatusOK)
	}
}

func RequireTokenAuthentication(res http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	authentication := authentication.InitJWTAuthentication()

	token, err := jwtRequest.ParseFromRequest(req, jwtRequest.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		} else {
			return authentication.PublicKey, nil
		}
	})

	if err == nil && token.Valid && !authentication.IsInBlacklist(req.Header.Get("Authorization")) {
		next(res, req)
	} else {
		res.WriteHeader(http.StatusUnauthorized)
	}
}
