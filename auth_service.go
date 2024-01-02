package main

import (
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	Secret []byte
}

func (as *AuthService) NewToken(userId string) (*string, error) {
	newJwt := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Subject: userId,
		},
	)
	token, err := newJwt.SignedString(as.Secret)

	if err != nil {
		log.Printf("Unexpected token signing error: %s", err.Error())
		return nil, fmt.Errorf("unexpected token signing error: %s", err.Error())
	}

	return &token, nil

}
