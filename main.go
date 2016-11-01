package main

import (
	"net/http"
	"fmt"
	"github.com/nanopx/go-authentication-test/routers"
	"github.com/urfave/negroni"
)

func testApi(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API"))
}

var TestApi = http.HandlerFunc(testApi);

func main() {
	router := routers.Initialize()

	n := negroni.Classic()
	n.UseHandler(router)

	fmt.Println("Serving...")
	http.ListenAndServe(":3000", n)
}
