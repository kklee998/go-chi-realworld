package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type key string

const (
	userEmailKey key = "userEmail"
)

type AuthGuard struct {
	signingSecret []byte
}

func getTokenFromBearerHeader(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("authorization header not provided")
	}
	s := strings.Split(header, "Token ")
	if len(s) < 2 {
		return "", errors.New("authorization header not provided")
	}
	token := s[1]
	return token, nil
}

func (auth AuthGuard) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token, err := getTokenFromBearerHeader(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return auth.signingSecret, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userEmail, err := parsedToken.Claims.GetSubject()
		if err != nil {
			log.Printf("No subject found in token, %v", parsedToken.Claims)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx = context.WithValue(ctx, userEmailKey, userEmail)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)

	})
}
