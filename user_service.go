package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kklee998/go-chi-realworld/db"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUsernameOrEmailAlreadyInUse = errors.New("username or email already in use")
)

type UserService struct {
	conn        *pgx.Conn
	queries     *db.Queries
	authService *AuthService
}

func (us *UserService) NewUser(ctx context.Context, newUser NewUser) (*User, error) {
	tx, err := us.conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to start a pgx transaction: %s", err.Error())
	}
	defer tx.Rollback(ctx)
	qtx := us.queries.WithTx(tx)

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
				log.Printf("Unhandled Postgres Error in NewUser: %s", pgErr.Message)
				return nil, fmt.Errorf("unhandled Postgres error: %s", pgErr.Message)
			}

		} else {
			log.Printf("Unhandled Error in NewUser: %s", err.Error())
			return nil, fmt.Errorf("unhandled error: %s", err.Error())
		}
	}

	token, err := us.authService.NewToken(userResult.Email)
	if err != nil {
		return nil, err
	}
	user := User{
		ID:       userResult.ID,
		Username: userResult.Username,
		Email:    userResult.Email,
		Token:    *token,
		Bio:      userResult.Bio.String,
		Image:    userResult.Bio.String,
	}

	tx.Commit(ctx)

	return &user, nil

}

func (us *UserService) UpdateUser(ctx context.Context, existingUser User, updateUser UpdateUser) (*User, error) {
	tx, err := us.conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to start a pgx transaction: %s", err.Error())
	}
	defer tx.Rollback(ctx)
	qtx := us.queries.WithTx(tx)

	var updateUserParams db.UpdateUserParams
	var token *string

	updateUserParams.ID = existingUser.ID
	if updateUser.Bio != nil {
		updateUserParams.Bio = pgtype.Text{String: *updateUser.Bio, Valid: true}
	} else {
		updateUserParams.Bio = pgtype.Text{String: existingUser.Bio, Valid: true}
	}
	if updateUser.Image != nil {
		updateUserParams.Image = pgtype.Text{String: *updateUser.Image, Valid: true}
	} else {
		updateUserParams.Image = pgtype.Text{String: existingUser.Image, Valid: true}
	}
	if updateUser.Email != nil {
		updateUserParams.Email = *updateUser.Email
	} else {
		updateUserParams.Email = existingUser.Email
	}
	if updateUser.Username != nil {
		updateUserParams.Username = *updateUser.Username
	} else {
		updateUserParams.Username = existingUser.Username
	}

	updatedUserResult, err := qtx.UpdateUser(ctx, updateUserParams)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Printf("Unhandled Postgres Error in UpdateUser: %s", pgErr.Message)
			return nil, fmt.Errorf("unhandled Postgres error: %s", pgErr.Message)

		} else {
			log.Printf("Unhandled Error in UpdateUser: %s", err.Error())
			return nil, fmt.Errorf("unhandled error: %s", err.Error())
		}
	}

	if updateUser.Password != nil {
		log.Println("Updating User Password")
		unhashedPassword := []byte(*updateUser.Password)
		bcryptHash, _ := bcrypt.GenerateFromPassword(unhashedPassword, 10)
		hashedPassword := string(bcryptHash)

		err := qtx.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{
			UserID:   pgtype.Int4{Int32: updatedUserResult.ID, Valid: true},
			Password: hashedPassword,
		})
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				log.Printf("Unhandled Postgres Error in UpdateUserPassword: %s", pgErr.Message)
				return nil, fmt.Errorf("unhandled Postgres error: %s", pgErr.Message)

			} else {
				log.Printf("Unhandled Error in UpdateUserPassword: %s", err.Error())
				return nil, fmt.Errorf("unhandled error: %s", err.Error())
			}
		}

		token, err = us.authService.NewToken(updatedUserResult.Email)
		if err != nil {
			return nil, err
		}

	}

	tx.Commit(ctx)

	if token == nil {
		token = new(string)
	}

	user := User{
		ID:       updatedUserResult.ID,
		Username: updatedUserResult.Username,
		Email:    updatedUserResult.Email,
		Token:    *token,
		Bio:      updatedUserResult.Bio.String,
		Image:    updatedUserResult.Bio.String,
	}
	return &user, nil
}
