package v1

import (
	"github.com/gorilla/mux"
	//"github.com/nanopx/go-authentication-test/routers/helpers"
	//handlers "github.com/nanopx/go-authentication-test/handlers/v1"
	"github.com/nanopx/go-authentication-test/config"
	"fmt"
	"github.com/nanopx/go-authentication-test/handlers"
	"github.com/nanopx/go-authentication-test/routers/helpers"
)

func SetRoutes(router *mux.Router) {
	// Handle POST /authentication/token
	router.HandleFunc("/authentication/token", handlers.Login).Methods("POST")

	// Handle GET /authentication/token-refresh
	router.Handle("/authentication/token-refresh", helpers.ApplyHandlers(
		handlers.RequireTokenAuthentication,
		handlers.RefreshToken,
	)).Methods("POST")

	// Handle GET /authentication/logout
	router.Handle("/authentication/logout", helpers.ApplyHandlers(
		handlers.RequireTokenAuthentication,
		handlers.Logout,
	)).Methods("GET")

	// Handle GET /ping
	router.Handle("/ping", helpers.ApplyHandlers(
		handlers.PingHandler,
	)).Methods("GET")

	//appConfig := config.Get()
	//fmt.Print(appConfig.PublicKeyPath)
}

