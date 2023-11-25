// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: query.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const createNewUser = `-- name: CreateNewUser :one
INSERT INTO users (email, username, password)
VALUES ($1, $2, $3)
RETURNING id, email, username, password, bio, image
`

type CreateNewUserParams struct {
	Email    string
	Username string
	Password string
}

func (q *Queries) CreateNewUser(ctx context.Context, arg CreateNewUserParams) (User, error) {
	row := q.db.QueryRow(ctx, createNewUser, arg.Email, arg.Username, arg.Password)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Username,
		&i.Password,
		&i.Bio,
		&i.Image,
	)
	return i, err
}

const getUser = `-- name: GetUser :one
SELECT id, email, username, password, bio, image
FROM users
WHERE id = $1
`

func (q *Queries) GetUser(ctx context.Context, id int32) (User, error) {
	row := q.db.QueryRow(ctx, getUser, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Username,
		&i.Password,
		&i.Bio,
		&i.Image,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET email = $2,
    username = $3,
    password = $4,
    bio = $5,
    image = $6
WHERE id = $1
RETURNING id, email, username, password, bio, image
`

type UpdateUserParams struct {
	ID       int32
	Email    string
	Username string
	Password string
	Bio      pgtype.Text
	Image    pgtype.Text
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRow(ctx, updateUser,
		arg.ID,
		arg.Email,
		arg.Username,
		arg.Password,
		arg.Bio,
		arg.Image,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Username,
		&i.Password,
		&i.Bio,
		&i.Image,
	)
	return i, err
}
