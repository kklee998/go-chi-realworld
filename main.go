package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type NewUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
type User struct {
	Email    string `json:"email"`
	Token    string `json:"token"`
	Username string `json:"username"`
	Bio      string `json:"bio"`
	Image    string `json:"image"`
}
type UserResponse struct {
	User User `json:"user"`
}

type Errors struct {
	Body []string `json:"body"`
}

type GenericErrorModel struct {
	Errors Errors `json:"errors"`
}

func main() {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"message": "Hello World"}`))
	})

	r.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		var newUserRequest NewUserRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&newUserRequest)
		if err != nil {
			log.Fatalf("Unable to decode NewUserRequest, %s", err.Error())
		}

		userResponse := UserResponse{User: User{
			Username: newUserRequest.Username,
			Email:    newUserRequest.Email,
			Token:    "",
			Bio:      "",
			Image:    "",
		}}

		encoder := json.NewEncoder(w)
		encoder.Encode(userResponse)
	})
	http.ListenAndServe(":8080", r)
}
