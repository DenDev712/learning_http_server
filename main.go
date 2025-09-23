package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"database/sql"
	"os"

	"github.com/DenDev712/learning_http_server/internal/auth"
	"github.com/DenDev712/learning_http_server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// handler for readiness
func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain ; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// will be used to increment safely across multiple goroutines
type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	PLATFORM       string
	JWT_SECRET     string
}

// middleware to increment the counter
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// metrics handler to show the hits
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html ; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	html := fmt.Sprintf(
		`<html> 
	    	<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</html>`, cfg.fileserverHits.Load())

	w.Write([]byte(html))
}

// reset handler to reset the counter
func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain ; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

// json response helper
func writeJSON(w http.ResponseWriter, status int, v interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	response, err := json.MarshalIndent(v, " ", "  ")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}
	w.Write(response)
	return nil
}

// error helper
func respondWithError(w http.ResponseWriter, status int, msg string) error {
	return writeJSON(w, status, map[string]string{"error": msg})
}

// censor word
func censorWord(input string) string {
	//list of censored words
	var censoredWords = []string{"kerfuffle", "sharbert", "fornax"}
	//split each word of the input
	words := strings.Split(input, " ")
	//iterate through them
	for i, word := range words {
		//lowercase
		lower := strings.ToLower(word)
		//if they contain a bad word replace with * of same length
		for _, bad := range censoredWords {
			if lower == bad {
				words[i] = strings.Repeat("*", len(word))
			}
		}
	}
	return strings.Join(words, " ")
}

type createChirpReq struct {
	Body    string `json:"body"`
	User_Id string `json:"user_id"`
}

// json handler
func (cfg *apiConfig) jsonvalidateChirp(w http.ResponseWriter, r *http.Request) {

	//get token
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "could not get token")
		return
	}

	//validate the token
	userID, err := auth.ValidateJWT(tokenStr, cfg.JWT_SECRET)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid token")
		return
	}

	//decode the json
	var req createChirpReq
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		//if the body was empty
		if err == io.EOF {
			respondWithError(w, http.StatusBadRequest, "Request body required")
			return
		}
		//if it was invalid
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	//if its empty or too long
	if strings.TrimSpace(req.Body) == "" {
		respondWithError(w, http.StatusBadRequest, "Missing chirp body")
		return
	}

	if utf8.RuneCountInString(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp body is too long")
		return
	}

	cleaned := censorWord(req.Body)
	//storing chirp in db
	chirp, err := cfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleaned,
		UserID: userID,
	})
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not create chirpy")
		return
	}
	//if it passes all checks
	writeJSON(w, http.StatusCreated, chirp)
}

type createUserReq struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

// users handler
func (cfg *apiConfig) handlerUsers(w http.ResponseWriter, r *http.Request) {

	//parse json
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON :( ")
		return
	}

	//check if the email is empty
	if strings.TrimSpace(req.Email) == "" {
		respondWithError(w, http.StatusBadRequest, "Missing Email :(")
		return
	}

	//check if the password is empty
	if strings.TrimSpace(req.Password) == "" {
		respondWithError(w, http.StatusBadRequest, "Missing password :(")
		return
	}

	//hashing the password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to hash the password :(")
	}
	//create user in db
	user, err := cfg.DB.CreateUser(r.Context(), database.CreateUserParams{
		Email: req.Email, HashedPasswords: hashedPassword,
	})
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not create user :(")
		return
	}

	response := map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email,
		"created_at": user.CreatedAt,
		"updated_at": user.UpdatedAt,
	}

	//respond
	writeJSON(w, http.StatusCreated, response)
}

type loginReq struct {
	Password         string `json:"password"`
	Email            string `json:"email"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

// handle login
func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not decode the JSON :(")
		return
	}

	// Lookup user by email
	user, err := cfg.DB.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	// Compare the hashed password
	if err := auth.CheckPasswordHash(req.Password, user.HashedPasswords); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	const defaultExpiration = time.Hour

	// Create an access JWT token
	token, err := auth.MakeJWT(user.ID, cfg.JWT_SECRET, defaultExpiration)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create JWT :(")
		return
	}

	//creating a refresh token
	refresh_token, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not access refresh token :(")
		return
	}
	//expires after 60 days
	expiresAt := time.Now().Add(60 * 24 * time.Hour)

	err = cfg.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refresh_token,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		RevokedAt: sql.NullTime{Valid: false},
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not save refresh token :(")
		return
	}
	// Build response
	response := map[string]interface{}{
		"id":            user.ID,
		"email":         user.Email,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
		"token":         token,
		"refresh_token": refresh_token,
	}

	writeJSON(w, http.StatusOK, response)
}

// handle refresh
func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	//extracting the refresh token
	refreshTokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "refresh token required")
		return
	}

	//look up the refresh token in db
	refreshToken, err := cfg.DB.GetRefreshToken(r.Context(), refreshTokenStr)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	//check if the token is expired
	now := time.Now()
	if refreshToken.RevokedAt.Valid || refreshToken.ExpiresAt.Before(now) {
		respondWithError(w, http.StatusUnauthorized, "Token has expired bro ")
		return
	}

	//generating a new refresh token
	newJWT, err := auth.MakeJWT(refreshToken.UserID, cfg.JWT_SECRET, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not generate refresh token")
		return
	}

	//returning the new jwt
	writeJSON(w, http.StatusOK, map[string]string{
		"token": newJWT,
	})
}

// revoking the rjwt
func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	//extracting the refresh token
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "could not find the token")
		return
	}

	//verifying the token
	_, err = cfg.DB.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "refresh token not found")
		return
	}

	//revoking
	err = cfg.DB.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not revoke the token bro")
		return
	}

	//204 response
	w.WriteHeader(http.StatusNoContent)

}

// handle to delete all users
func (cfg *apiConfig) handlerAdminReset(w http.ResponseWriter, r *http.Request) {
	if cfg.PLATFORM != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	err := cfg.DB.DeleteAllUsers(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to reset users")
		return
	}

	writeJSON(w, http.StatusOK, "All users deleted lol")
}

// retrieving chirps handler
func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.DB.GetChirps(r.Context())
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not retrieve the chirps :(")
		return
	}

	writeJSON(w, http.StatusOK, chirps)
}

// retriving chirps by id
func (cfg *apiConfig) handlerGetChirpsById(w http.ResponseWriter, r *http.Request) {
	//extracting the chirps id
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}
	chirpIDStr := parts[3]

	//parse the chirp id to uuid
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not parse the chirp id :(")
		return
	}

	chirp, err := cfg.DB.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not retrieve the chirp from the database :(")
		return
	}

	writeJSON(w, http.StatusOK, chirp)
}

func main() {

	//load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}
	//get the db url from .env file
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL not set in .env file")
	}
	//get the platform
	dbplatform := os.Getenv("PLATFORM")
	if dbplatform == "" {
		log.Fatal("PLATFORM not set in .env file")
	}
	//connect to db
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}
	defer db.Close()

	//get the jwt_secret from .env
	jwt_secret := os.Getenv("JWT_SECRET")
	if jwt_secret == "" {
		log.Fatal("Could not find JWT_SECRET gang")
	}
	//create sqlc queries instance
	dbQueries := database.New(db)

	//store in the apiConfig so the handlers can use it
	cfg := &apiConfig{
		DB:         dbQueries,
		PLATFORM:   dbplatform,
		JWT_SECRET: jwt_secret,
	}

	//holds the counter
	mux := http.NewServeMux()

	//for index.html
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	//for assets/logo.png
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))

	//for readiness endpoint
	mux.HandleFunc("GET /admin/healthz", readinessHandler)

	//metrics endpoint
	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandler)

	//reset endpoint
	mux.HandleFunc("POST /admin/reset", cfg.resetHandler)

	//message chirpy json endpoint
	mux.HandleFunc("POST /api/chirps", cfg.jsonvalidateChirp)

	// Use apiCfg in your routes:
	mux.HandleFunc("POST /api/users", cfg.handlerUsers)

	//delete users
	mux.HandleFunc("POST /admin/resetUser", cfg.handlerAdminReset)

	//get chirps
	mux.HandleFunc("GET /api/chirps", cfg.handlerGetChirps)

	//get chirps by id
	mux.HandleFunc("GET /api/chirps/{chirpsID}", cfg.handlerGetChirpsById)

	//login endpoint
	mux.HandleFunc("POST /api/login", cfg.handleLogin)

	//refresh token endpoint
	mux.HandleFunc("POST /api/refresh", cfg.handleRefresh)

	//revoking token endpoint
	mux.HandleFunc("POST /api/revoke", cfg.handleRevoke)

	server := &http.Server{ // Create the server
		Addr:    ":8080",
		Handler: mux, // Bind to localhost:8080
	}

	log.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
