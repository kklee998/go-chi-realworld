package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kklee998/go-chi-realworld/db"
	"golang.org/x/crypto/bcrypt"
)

type NewUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type NewUserRequest struct {
	NewUser NewUser `json:"user"`
}

type User struct {
	Email    string `json:"email"`
	Token    string `json:"token"`
	Username string `json:"username"`
	Bio      string `json:"bio"`
	Image    string `json:"image"`
}

type UpdateUser struct {
	Email    string `json:"email"`
	Token    string `json:"token"`
	Username string `json:"username"`
	Bio      string `json:"bio"`
	Image    string `json:"image"`
}

type UpdateUserRequest struct {
	UpdateUser UpdateUser `json:"user"`
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

type LoginUserRequest struct {
	LoginUser LoginUser `json:"user"`
}

type LoginUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func HelloWorld(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"message": "Hello World"}`))
}

func main() {
	port := "8080"
	r := chi.NewRouter()

	ctx := context.Background()

	conn, err := pgx.Connect(ctx, "postgres://postgres:postgres@localhost:5432/example")
	if err != nil {
		log.Fatalf(err.Error())
	}
	defer conn.Close(ctx)

	queries := db.New(conn)

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	r.Get("/", HelloWorld)

	r.Route("/users", func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var newUserRequest NewUserRequest
			decoder := json.NewDecoder(r.Body)
			err := decoder.Decode(&newUserRequest)
			if err != nil {
				log.Fatalf("Unable to decode NewUserRequest, %s", err.Error())
			}

			unhashedPassword := []byte(newUserRequest.NewUser.Password)
			bcryptHash, _ := bcrypt.GenerateFromPassword(unhashedPassword, 10)
			hashedPassword := string(bcryptHash)

			newUserParam := db.CreateNewUserParams{
				Username: newUserRequest.NewUser.Username,
				Email:    newUserRequest.NewUser.Username,
				Password: hashedPassword,
			}
			user, err := queries.CreateNewUser(ctx, newUserParam)
			if err != nil {
				log.Println(err.Error())
			}

			userResponse := UserResponse{User: User{
				Username: user.Username,
				Email:    user.Email,
				Token:    "",
				Bio:      user.Bio.String,
				Image:    user.Bio.String,
			}}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})

		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			var LoginUserRequest LoginUserRequest
			decoder := json.NewDecoder(r.Body)
			err := decoder.Decode(&LoginUserRequest)
			if err != nil {
				log.Fatalf("Unable to decode LoginUserRequest, %s", err.Error())
			}

			user, err := queries.GetUserWithPassword(ctx, LoginUserRequest.LoginUser.Username)
			if err != nil {
				log.Println(err.Error())
			}

			hashedPassword := []byte(user.Password)
			password := []byte(LoginUserRequest.LoginUser.Password)
			bcrypt.CompareHashAndPassword(hashedPassword, password)

			if err != nil {
				log.Println(err.Error())
			}

			sessionToken, err := GenerateRandomStringURLSafe(32)
			if err != nil {
				log.Println(err.Error())
			}

			queries.CreateSession(ctx, db.CreateSessionParams{
				UserID:       pgtype.Int4{Int32: user.ID, Valid: true},
				SessionToken: sessionToken,
			})

			if err != nil {
				log.Println(err.Error())
			}

			userResponse := UserResponse{User: User{
				Username: user.Username,
				Email:    user.Email,
				Token:    sessionToken,
				Bio:      user.Bio.String,
				Image:    user.Image.String,
			}}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})
	})

	r.Route("/user", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			userResponse := UserResponse{User: User{
				Username: "",
				Email:    "",
				Token:    "",
				Bio:      "",
				Image:    "",
			}}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})

		r.Put("/", func(w http.ResponseWriter, r *http.Request) {
			var updateUserRequest UpdateUserRequest
			decoder := json.NewDecoder(r.Body)
			err := decoder.Decode(&updateUserRequest)
			if err != nil {
				log.Fatalf("Unable to decode UpdateUserRequest, %s", err.Error())
			}

			userResponse := UserResponse{User: User{
				Username: updateUserRequest.UpdateUser.Username,
				Email:    updateUserRequest.UpdateUser.Email,
				Token:    "",
				Bio:      "",
				Image:    "",
			}}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})
	})

	log.Printf("Starting Server on Port %s", port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), r)
}

// GenerateRandomStringURLSafe returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
