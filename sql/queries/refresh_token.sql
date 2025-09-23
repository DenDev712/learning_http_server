-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, user_id, expires_at,revoked_at)
VALUES ($1, $2, $3, $4);

-- name: GetRefreshToken :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at
FROM refresh_tokens
WHERE token = $1;       