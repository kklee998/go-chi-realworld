package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kklee998/go-chi-realworld/db"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrEmailNotFound        = errors.New("email not found")
	ErrPasswordDoesNotMatch = errors.New("passwords do not match")
)

type AuthService struct {
	secret  []byte
	queries *db.Queries
}

func (as *AuthService) NewToken(userEmail string) (*string, error) {
	newJwt := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Subject: userEmail,
		},
	)
	token, err := newJwt.SignedString(as.secret)

	if err != nil {
		log.Printf("Unexpected token signing error: %s", err.Error())
		return nil, fmt.Errorf("unexpected token signing error: %s", err.Error())
	}

	return &token, nil

}

func (as *AuthService) Login(ctx context.Context, email, password string) (*User, error) {
	userResult, err := as.queries.GetUserByEmailWithPassword(ctx, email)
	if err != nil {
		log.Println("Email not found.")
		return nil, ErrEmailNotFound
	}

	hashedPassword := []byte(userResult.Password)
	inputPassword := []byte(password)
	err = bcrypt.CompareHashAndPassword(hashedPassword, inputPassword)
	if err != nil {
		log.Println("Passwords does not match.")
		return nil, ErrPasswordDoesNotMatch
	}

	token, err := as.NewToken(userResult.Email)
	if err != nil {
		return nil, err
	}

	user := User{
		Username: userResult.Username,
		Email:    userResult.Email,
		Token:    *token,
		Bio:      userResult.Bio.String,
		Image:    userResult.Bio.String,
	}

	return &user, nil
}
