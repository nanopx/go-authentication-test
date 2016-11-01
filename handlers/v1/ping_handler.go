package v1

import "net/http"

func PingHandler(res http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	res.Write([]byte("pong"))
}
