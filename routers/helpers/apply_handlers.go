package helpers

import (
	"net/http"
	"github.com/urfave/negroni"
)

type T func(res http.ResponseWriter, req *http.Request, next http.HandlerFunc)

func ApplyHandlers(handlers ...T) *negroni.Negroni {
	n := negroni.New()
	for _, handler := range handlers {
		n.Use(negroni.HandlerFunc(handler))
	}
	return n
}