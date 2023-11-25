-- name: GetUser :one
SELECT *
FROM users
WHERE id = $1;
-- name: GetUserWithPassword :one
SELECT users.*,
    user_passwords.password
from users
    INNER JOIN user_passwords ON users.id = user_passwords.user_id
WHERE users.username = $1;
-- name: CreateNewUser :one
WITH new_user AS (
    INSERT INTO users(username, email)
    VALUES($1, $2)
    RETURNING *
),
new_user_password AS (
    INSERT INTO user_passwords(user_id, password)
    SELECT id,
        $3
    from new_user
)
SELECT *
FROM new_user;
-- name: UpdateUser :one
UPDATE users
SET email = $2,
    username = $3,
    bio = $4,
    image = $5
WHERE id = $1
RETURNING *;
-- name: UpdateUserPassword :exec
UPDATE user_passwords
SET password = $2
WHERE user_id = $1;
-- name: CreateSession :exec
INSERT INTO user_sessions(user_id, session_token)
VALUES($1, $2);