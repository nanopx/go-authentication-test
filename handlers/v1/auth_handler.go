package v1

import (
	"net/http"
	"github.com/nanopx/go-authentication-test/services/models"
	"encoding/json"
	"github.com/nanopx/go-authentication-test/services"
)

func Login(res http.ResponseWriter, req *http.Request) {
	requestUser := new(models.User)
	decoder := json.NewDecoder(req.Body)
	decoder.Decode(&requestUser)

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

}

//import (
//	"net/http"
//	"github.com/dgrijalva/jwt-go"
//	"time"
//	"context"
//	"fmt"
//)
//
//type Key int
//const AppKey Key = 0
//type Secret string
//const AppSecret Secret = "SECRET..."
//
//type Claims struct {
//	Username string `json:"username"`
//	jwt.StandardClaims
//}
//
//// Create a JWT and place it in the client's cookie
//func setToken(w http.ResponseWriter, r *http.Request) {
//
//	// Expires the token and cookie in 1 hour
//	expireToken := time.Now().Add(time.Hour * 1).Unix()
//	expireCookie := time.Now().Add(time.Hour * 1)
//
//	claims := Claims{
//		"testuser",
//		jwt.StandardClaims{
//			ExpiresAt: expireToken,
//			Issuer: "localhost:9000",
//		},
//	}
//
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//
//	signedToken, _ := token.SignedString([]byte(AppSecret))
//
//	cookie := http.Cookie{
//		Name: "Auth",
//		Value: signedToken,
//		Expires: expireCookie,
//		HttpOnly: true,
//	}
//
//	http.SetCookie(w, &cookie)
//}
//
//// Middleware to protect invalid JWT
//func ValidateToken(protectedPage http.HandlerFunc) http.HandlerFunc {
//	fmt.Print("FOOO1")
//	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
//
//		// If no Auth cookie is set then return a 404 not found
//		cookie, err := r.Cookie("Auth")
//		if err != nil {
//			http.Error(w, "Unauthorized", 401)
//			return
//		}
//
//		// Return a Token using the cookie
//		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
//			// Make sure token's signature wasn't changed
//			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
//				return nil, fmt.Errorf("Unexpected siging method")
//			}
//			return []byte(AppSecret), nil
//		})
//
//		fmt.Print(token, err)
//		if err != nil {
//			http.Error(w, "Unauthorized", 401)
//			return
//		}
//
//		// Grab the tokens claims and pass it into the original request
//		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
//			ctx := context.WithValue(r.Context(), AppKey, *claims)
//			protectedPage(w, r.WithContext(ctx))
//		} else {
//			http.Error(w, "Unauthorized", 401)
//			return
//		}
//	})
//}
//
//// only viewable if the client has a valid token
//func Protect(protectedPage http.HandlerFunc) http.HandlerFunc {
//	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
//		claims, ok := r.Context().Value(AppKey).(Claims)
//		if !ok {
//			http.Error(w, "Unauthorized", 401)
//			return
//		}
//
//		fmt.Fprintf(w, "Hello %s", claims.Username)
//
//		protectedPage(w, r)
//	})
//}
//
//func logout(w http.ResponseWriter, r *http.Request) {
//	deleteCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
//	http.SetCookie(w, &deleteCookie)
//	return
//}
//
//var Logout = http.HandlerFunc(logout);
//var SetToken = http.HandlerFunc(setToken);