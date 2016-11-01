package routers

import (
	"github.com/gorilla/mux"
	"github.com/nanopx/go-authentication-test/routers/v1"
	"net/http"
	"github.com/nanopx/go-authentication-test/handlers"
)

func Initialize() *mux.Router {
	router := mux.NewRouter()

	// Mount /v1 routes
	v1Router := router.PathPrefix("/v1").Subrouter()
	v1.SetRoutes(v1Router)

	// Handle 404
	router.NotFoundHandler = http.HandlerFunc(func (res http.ResponseWriter, req *http.Request) {
		handlers.ErrorHandler(res, req, 404, "Not Found")
	})

	return router
}