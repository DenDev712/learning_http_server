-- name: CreateUser :one

INSERT INTO users(id, created_at, updated_at, email, hashed_passwords, is_chirpy_red)
VALUES(
	gen_random_uuid(),
	NOW(),
	NOW(),
	$1,
	$2, 
	FALSE

)
RETURNING *;

-- name: GetUserByEmail :one 
SELECT id, created_at, updated_at, email, hashed_passwords, is_chirpy_red
FROM users
WHERE email = $1;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: UpdateUser :one
UPDATE users 
SET email = $2,
	hashed_passwords = $3,
	updated_at = NOW()
WHERE id = $1 
RETURNING id, created_at, updated_at, email, hashed_passwords, is_chirpy_red;


-- name: UpgdradeUserRed :exec
UPDATE users
SET is_chirpy_red = TRUE,
	updated_at = NOW()
WHERE id = $1;