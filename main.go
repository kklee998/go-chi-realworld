package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/kklee998/go-chi-realworld/db"

	_ "github.com/joho/godotenv/autoload"
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
	ID       int32  `json:"-"`
	Email    string `json:"email"`
	Token    string `json:"token"`
	Username string `json:"username"`
	Bio      string `json:"bio"`
	Image    string `json:"image"`
}

type UpdateUser struct {
	Email    *string `json:"email,omitempty"`
	Password *string `json:"Password,omitempty"`
	Username *string `json:"username,omitempty"`
	Bio      *string `json:"bio,omitempty"`
	Image    *string `json:"image,omitempty"`
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
	Email    string `json:"email"`
	Password string `json:"password"`
}

func HelloWorld(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"message": "Hello World"}`))
}

func main() {
	secret, ok := os.LookupEnv("SECRET")
	if !ok {
		log.Fatalln("SECRET env var not set")
	}
	secretKey := []byte(secret)
	port := "8080"
	r := chi.NewRouter()

	ctx := context.Background()

	conn, err := pgx.Connect(ctx, "postgres://postgres:postgres@localhost:5432/example")
	if err != nil {
		log.Fatalf(err.Error())
	}
	defer conn.Close(ctx)

	queries := db.New(conn)
	authGuard := AuthGuard{
		queries:       queries,
		signingSecret: secretKey,
	}

	authService := AuthService{
		queries: queries,
		secret:  secretKey,
	}
	userService := UserService{
		conn:        conn,
		queries:     queries,
		authService: &authService,
	}

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
				log.Printf("Unable to decode JSON: %s", err.Error())
				ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}

			user, err := userService.NewUser(ctx, newUserRequest.NewUser)
			if err != nil {
				if errors.Is(err, ErrUsernameOrEmailAlreadyInUse) {
					ErrorResponse(w, "Username or email already in use.", http.StatusUnprocessableEntity)
					return
				} else {
					ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			userResponse := UserResponse{User: *user}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})

		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			var loginUserRequest LoginUserRequest
			decoder := json.NewDecoder(r.Body)
			err := decoder.Decode(&loginUserRequest)
			if err != nil {
				log.Printf("Unable to decode JSON: %s", err.Error())
				ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}

			user, err := authService.Login(ctx, loginUserRequest.LoginUser.Email, loginUserRequest.LoginUser.Password)

			if err != nil {
				if errors.Is(err, ErrEmailNotFound) || errors.Is(err, ErrPasswordDoesNotMatch) {
					ErrorResponse(w, "Email or Password invalid.", http.StatusUnauthorized)
					return
				} else {
					ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			userResponse := UserResponse{User: *user}
			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})
	})

	r.Route("/user", func(r chi.Router) {
		r.Use(authGuard.AuthRequired)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			user := ctx.Value(userKey).(User)

			userResponse := UserResponse{User: user}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})

		r.Put("/", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var updateUserRequest UpdateUserRequest

			decoder := json.NewDecoder(r.Body)
			err := decoder.Decode(&updateUserRequest)
			if err != nil {
				log.Printf("Unable to decode JSON: %s", err.Error())
				ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			user := ctx.Value(userKey).(User)

			updatedUser, err := userService.UpdateUser(ctx, user, updateUserRequest.UpdateUser)
			if err != nil {
				ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			userResponse := UserResponse{User: *updatedUser}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})
	})

	log.Printf("Starting Server on Port %s", port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), r)
}

func ErrorResponse(w http.ResponseWriter, err string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	var errorBody []string
	errorBody = append(errorBody, err)
	erorResponse := GenericErrorModel{Errors: Errors{Body: errorBody}}
	json.NewEncoder(w).Encode(erorResponse)
}
