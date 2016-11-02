package v1

import (
	"github.com/gorilla/mux"
	"github.com/nanopx/go-authentication-test/routers/helpers"
	handlers "github.com/nanopx/go-authentication-test/handlers/v1"
)

func SetRoutes(router *mux.Router) *mux.Router {
	// Handle POST /auth/token
	router.HandleFunc("/auth/token", handlers.Login).Methods("POST")

	// Handle GET /auth/token-refresh
	router.Handle("/auth/token-refresh", helpers.ApplyHandlers(
		handlers.RequireTokenAuthentication,
		handlers.RefreshToken,
	)).Methods("POST")

	// Handle GET /auth/logout
	router.Handle("/auth/logout", helpers.ApplyHandlers(
		handlers.RequireTokenAuthentication,
		handlers.Logout,
	)).Methods("GET")

	// Handle GET /ping
	router.Handle("/ping", helpers.ApplyHandlers(
		handlers.PingHandler,
	)).Methods("GET")

	// Handle GET /hidden/ping
	router.Handle("/hidden/ping", helpers.ApplyHandlers(
		handlers.RequireTokenAuthentication,
		handlers.PingHandler,
	)).Methods("GET")

	return router
}

