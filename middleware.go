package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/kklee998/go-chi-realworld/db"
)

type key string

const (
	userKey key = "user"
)

type AuthGuard struct {
	SessionStore *db.Queries
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
		session, err := auth.SessionStore.GetUserBySessionToken(ctx, token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx = context.WithValue(ctx, userKey, session)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)

	})
}
