-- name: CreateUser :one

INSERT INTO users(id, created_at, updated_at, email, hashed_passwords)
VALUES(
	gen_random_uuid(),
	NOW(),
	NOW(),
	$1,
	$2

)
RETURNING *;

-- name: GetUserByEmail :one 
SELECT id, created_at, updated_at, email, hashed_passwords
FROM users
WHERE email = $1;

-- name: DeleteAllUsers :exec
DELETE FROM users;

