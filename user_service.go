package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kklee998/go-chi-realworld/db"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUsernameOrEmailAlreadyInUse = errors.New("username or email already in use")
)

type UserService struct {
	Conn        *pgx.Conn
	Queries     *db.Queries
	AuthService *AuthService
}

func (us *UserService) NewUser(ctx context.Context, newUser NewUser) (*User, error) {
	tx, err := us.Conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to start a pgx transaction: %s", err.Error())
	}
	defer tx.Rollback(ctx)
	qtx := us.Queries.WithTx(tx)

	unhashedPassword := []byte(newUser.Password)
	bcryptHash, _ := bcrypt.GenerateFromPassword(unhashedPassword, 10)
	hashedPassword := string(bcryptHash)

	newUserParam := db.CreateNewUserParams{
		Username: newUser.Username,
		Email:    newUser.Email,
		Password: hashedPassword,
	}
	userResult, err := qtx.CreateNewUser(ctx, newUserParam)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				return nil, ErrUsernameOrEmailAlreadyInUse
			} else {
				log.Printf("Unhandled Postgres Error: %s", pgErr.Message)
				return nil, fmt.Errorf("unhandled Postgres error: %s", pgErr.Message)
			}

		} else {
			log.Printf("Unhandled Error: %s", err.Error())
			return nil, fmt.Errorf("unhandled Error: %s", err.Error())
		}
	}

	token, err := us.AuthService.NewToken(userResult.Email)
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

	tx.Commit(ctx)

	return &user, nil

}
