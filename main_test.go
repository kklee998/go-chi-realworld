package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGETHelloWorld(t *testing.T) {

	request, _ := http.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	HelloWorld(response, request)

	got := response.Body.String()
	want := `{"message": "Hello World"}`

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
