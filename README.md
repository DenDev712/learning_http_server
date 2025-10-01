# Chirpy API (Learning Purposes) 🐦

A simple REST API written in **Go** to learn how HTTP servers work.  
The API allows users to register, log in, post "chirps" (short messages), manage authentication with JWTs and refresh tokens, and interact with Polka webhooks.

---

## 📚 Features

- **User Management**
  - Register a new user (`POST /api/users`)
  - Update email and password (`PUT /api/users`)
  - Login with JWT and refresh token support (`POST /api/login`)
  - Refresh access tokens (`POST /api/refresh`)
  - Revoke refresh tokens (`POST /api/revoke`)
  - Admin-only endpoint to delete all users (restricted by environment)

- **Chirps**
  - Create a chirp (`POST /api/chirps`)
  - Retrieve all chirps with optional sorting and filtering (`GET /api/chirps`)
    - `sort=asc|desc` → default is `asc`
    - `author_id=<uuid>` → filter chirps by a specific user
  - Retrieve a single chirp by ID (`GET /api/chirps/{chirpID}`)
  - Delete a chirp (only by owner) (`DELETE /api/chirps/{chirpID}`)

- **Polka Webhooks**
  - Webhook endpoint (`POST /api/polka/webhooks`)
  - Secured by an API key from `.env`
  - Handles `user.upgraded` events to mark users as **Chirpy Red**

- **Admin & Metrics**
  - Readiness probe (`GET /admin/healthz`)
  - Metrics page showing number of visits (`GET /admin/metrics`)
  - Reset visit counter (`POST /admin/reset`)

---

## ⚙️ Requirements

- Go 1.21+
- PostgreSQL
- `sqlc` generated queries (already included in `/internal/database`)
- Environment variables set in `.env`

---

## 🔑 Environment Variables

Create a `.env` file in the project root:

```env
DB_URL=postgres://user:password@localhost:5432/chirpy?sslmode=disable
PLATFORM=dev
JWT_SECRET=super_secret_key
POLKA_KEY=your_polka_api_key

```
---
## Learning Purpose
This project was built strictly for learning how http servers work
