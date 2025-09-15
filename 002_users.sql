-- +goose Up
CREATE TABLE users(
   id UUID PRIMARY KEY,
   created_at TIMESTAMP NOT NULL, 
   updated_at TIMESTAMP NOT NULL,
   body TEXT NOT NULL
   user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE

);

-- +goose DOWN
DROP TABLE chirps;

