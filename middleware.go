package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kklee998/go-chi-realworld/db"
)

type key string

const (
	userKey key = "user"
)

type AuthGuard struct {
	signingSecret []byte
	queries       *db.Queries
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
			ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return auth.signingSecret, nil
		})
		if err != nil {
			log.Printf("Token cannot be parsed or validated. Reason: %s", err.Error())
			ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userEmail, err := parsedToken.Claims.GetSubject()
		if err != nil {
			log.Printf("No subject found in token, %v", parsedToken.Claims)
			ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userResult, err := auth.queries.GetUserByEmail(ctx, userEmail)
		if err != nil {
			log.Println("User not found")
			ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user := User{
			ID:       userResult.ID,
			Username: userResult.Username,
			Email:    userResult.Email,
			Token:    token,
			Bio:      userResult.Bio.String,
			Image:    userResult.Bio.String,
		}
		ctx = context.WithValue(ctx, userKey, user)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)

	})
}
