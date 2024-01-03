package main

import (
	"context"
	"encoding/json"
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

	userHandler := UserHandler{
		authService: &authService,
		userService: &userService,
	}

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	r.Get("/", HelloWorld)

	r.Route("/users", func(r chi.Router) {
		r.Post("/", userHandler.Create)
		r.Post("/login", userHandler.Login)
	})

	r.Route("/user", func(r chi.Router) {
		r.Use(authGuard.AuthRequired)
		r.Get("/", userHandler.Get)
		r.Put("/", userHandler.Update)
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
