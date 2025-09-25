-- +goose Up
CREATE TABLE users(
   id UUID PRIMARY KEY,
   created_at TIMESTAMP NOT NULL, 
   updated_at TIMESTAMP NOT NULL,
   email TEXT UNIQUE NOT NULL,
   hashed_passwords TEXT NOT NULL DEFAULT 'unset',
   is_chirpy_red BOOLEAN NOT NULL DEFAULT FALSE
);

-- +goose Down
DROP TABLE users;
