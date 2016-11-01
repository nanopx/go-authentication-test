package handlers

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"io/ioutil"
)

func TestNotImplemented(t *testing.T) {
	var message string = "Not Found..."
	var testHandler = http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		ErrorHandler(res, req, 404, message)
	})

	ts := httptest.NewServer(testHandler)
	defer ts.Close()

	res, err := http.Get( ts.URL )
	if err != nil {
		t.Error("unexpected")
		return
	}

	if res.StatusCode != 404 {
		t.Error("Status code error")
		return
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error("Reading reponse body: %v", err)
		return
	}

	if string(b) != message {
		t.Error("Response body mismatch")
		return
	}
}