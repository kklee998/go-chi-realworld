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
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kklee998/go-chi-realworld/db"
	"golang.org/x/crypto/bcrypt"

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
	authGuard := AuthGuard{SessionStore: queries, signingSecret: secretKey}

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
				ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}

			unhashedPassword := []byte(newUserRequest.NewUser.Password)
			bcryptHash, _ := bcrypt.GenerateFromPassword(unhashedPassword, 10)
			hashedPassword := string(bcryptHash)

			newUserParam := db.CreateNewUserParams{
				Username: newUserRequest.NewUser.Username,
				Email:    newUserRequest.NewUser.Email,
				Password: hashedPassword,
			}
			user, err := queries.CreateNewUser(ctx, newUserParam)
			if err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) {
					if pgErr.Code == pgerrcode.UniqueViolation {
						ErrorResponse(w, "Username or email already in use.", http.StatusUnprocessableEntity)
					} else {
						log.Printf("Unhandled Postgres Error: %s", pgErr.Message)
						ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
					}

				} else {
					log.Printf("Unhandled Error: %s", err.Error())
					ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				}

				return
			}

			newJwt := jwt.NewWithClaims(jwt.SigningMethodHS256,
				jwt.RegisteredClaims{
					Subject: user.Username,
				},
			)
			token, err := newJwt.SignedString(secretKey)

			if err != nil {
				log.Printf("Unhandled Error: %s", err.Error())
				ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			userResponse := UserResponse{User: User{
				Username: user.Username,
				Email:    user.Email,
				Token:    token,
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
				ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}

			user, err := queries.GetUserByEmailWithPassword(ctx, LoginUserRequest.LoginUser.Email)
			if err != nil {
				log.Println("Email not found.")
				ErrorResponse(w, "Email or Password invalid.", http.StatusUnauthorized)
				return
			}

			hashedPassword := []byte(user.Password)
			password := []byte(LoginUserRequest.LoginUser.Password)
			err = bcrypt.CompareHashAndPassword(hashedPassword, password)
			if err != nil {
				log.Println("Passwords does not match.")
				ErrorResponse(w, "Email or Password invalid.", http.StatusUnauthorized)
				return
			}

			newJwt := jwt.NewWithClaims(jwt.SigningMethodHS256,
				jwt.RegisteredClaims{
					Subject: user.Email,
				},
			)
			token, err := newJwt.SignedString(secretKey)

			if err != nil {
				log.Printf("Unhandled Error: %s", err.Error())
				ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			userResponse := UserResponse{User: User{
				Username: user.Username,
				Email:    user.Email,
				Token:    token,
				Bio:      user.Bio.String,
				Image:    user.Image.String,
			}}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})
	})

	r.Route("/user", func(r chi.Router) {
		r.Use(authGuard.AuthRequired)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			uc := ctx.Value(userKey).(string)
			user, _ := queries.GetUserByEmail(ctx, uc)

			userResponse := UserResponse{User: User{
				Username: user.Username,
				Email:    user.Email,
				Bio:      user.Bio.String,
				Image:    user.Image.String,
			}}

			encoder := json.NewEncoder(w)
			encoder.Encode(userResponse)
		})

		r.Put("/", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			uc := ctx.Value(userKey).(string)
			var updateUserRequest UpdateUserRequest
			decoder := json.NewDecoder(r.Body)
			err := decoder.Decode(&updateUserRequest)
			if err != nil {
				log.Fatalf("Unable to decode UpdateUserRequest, %s", err.Error())
				ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			user, err := queries.GetUserByEmail(ctx, uc)
			if err != nil {
				log.Println("Email not found.")
				ErrorResponse(w, "Email invalid.", http.StatusUnauthorized)
				return
			}

			tx, err := conn.Begin(ctx)
			if err != nil {
				log.Fatalf("Unable to Begin a Transaction, %s", err.Error())
				ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer tx.Rollback(ctx)
			qtx := queries.WithTx(tx)

			var updateUserParams db.UpdateUserParams
			updateUserParams.ID = user.ID
			if updateUserRequest.UpdateUser.Bio != nil {
				updateUserParams.Bio = pgtype.Text{String: *updateUserRequest.UpdateUser.Bio, Valid: true}
			} else {
				updateUserParams.Bio = user.Bio
			}
			if updateUserRequest.UpdateUser.Image != nil {
				updateUserParams.Image = pgtype.Text{String: *updateUserRequest.UpdateUser.Image, Valid: true}
			} else {
				updateUserParams.Image = user.Image
			}
			if updateUserRequest.UpdateUser.Email != nil {
				updateUserParams.Email = *updateUserRequest.UpdateUser.Email
			} else {
				updateUserParams.Email = user.Email
			}
			if updateUserRequest.UpdateUser.Username != nil {
				updateUserParams.Username = *updateUserRequest.UpdateUser.Username
			} else {
				updateUserParams.Username = user.Username
			}

			updatedUser, err := qtx.UpdateUser(ctx, updateUserParams)
			if err != nil {
				log.Printf("Unable to update user due to %s.", err.Error())
				ErrorResponse(w, "Update User Fail", http.StatusBadRequest)
				return
			}

			if updateUserRequest.UpdateUser.Password != nil {
				log.Println("Updating User Password")
				unhashedPassword := []byte(*updateUserRequest.UpdateUser.Password)
				bcryptHash, _ := bcrypt.GenerateFromPassword(unhashedPassword, 10)
				hashedPassword := string(bcryptHash)

				err := qtx.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{
					UserID:   pgtype.Int4{Int32: user.ID, Valid: true},
					Password: hashedPassword,
				})
				if err != nil {
					log.Printf("Unable to update user password due to %s.", err.Error())
					ErrorResponse(w, "Update User Fail", http.StatusBadRequest)
					return
				}

			}

			tx.Commit(ctx)
			userResponse := UserResponse{User: User{
				Username: updatedUser.Username,
				Email:    updatedUser.Email,
				Token:    "",
				Bio:      updatedUser.Bio.String,
				Image:    updatedUser.Image.String,
			}}

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
