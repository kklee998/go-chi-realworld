package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type UserHandler struct {
	userService *UserService
	authService *AuthService
}

func (u *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var newUserRequest NewUserRequest
	ctx := r.Context()
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&newUserRequest)
	if err != nil {
		log.Printf("Unable to decode JSON: %s", err.Error())
		ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	user, err := u.userService.NewUser(ctx, newUserRequest.NewUser)
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
}

func (u *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginUserRequest LoginUserRequest
	ctx := r.Context()
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&loginUserRequest)
	if err != nil {
		log.Printf("Unable to decode JSON: %s", err.Error())
		ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	user, err := u.authService.Login(ctx, loginUserRequest.LoginUser.Email, loginUserRequest.LoginUser.Password)

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
}

func (u *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := ctx.Value(userKey).(User)

	userResponse := UserResponse{User: user}

	encoder := json.NewEncoder(w)
	encoder.Encode(userResponse)
}

func (u *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	var updateUserRequest UpdateUserRequest
	ctx := r.Context()

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&updateUserRequest)
	if err != nil {
		log.Printf("Unable to decode JSON: %s", err.Error())
		ErrorResponse(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	user := ctx.Value(userKey).(User)

	updatedUser, err := u.userService.UpdateUser(ctx, user, updateUserRequest.UpdateUser)
	if err != nil {
		ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	userResponse := UserResponse{User: *updatedUser}

	encoder := json.NewEncoder(w)
	encoder.Encode(userResponse)
}
