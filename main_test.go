package main_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGETHelloWorld(t *testing.T) {

	request, _ := http.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"message": "Hello World"}`))
	}(response, request)

	got := response.Body.String()
	want := `{"message": "Hello World"}`

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
