package handlers

import (
	"net/http"
)

func ErrorHandler(res http.ResponseWriter, req *http.Request, status int, message string) {
	res.WriteHeader(status)
	res.Write([]byte(message))
}