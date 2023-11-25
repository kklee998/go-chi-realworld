-- name: GetUser :one
SELECT *
FROM users
WHERE id = $1;
-- name: CreateNewUser :one
INSERT INTO users (email, username, password)
VALUES ($1, $2, $3)
RETURNING *;
-- name: UpdateUser :one
UPDATE users
SET email = $2,
    username = $3,
    password = $4,
    bio = $5,
    image = $6
WHERE id = $1
RETURNING *;