package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
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
	var req createChirpReq
	//decode the json
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

	//parsing user id to uuid
	userUUID, err := uuid.Parse(req.User_Id)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user id")
		return
	}

	//storing chirp in db
	chirp, err := cfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleaned,
		UserID: userUUID,
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

// handle the login
func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req createUserReq

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not decode the json :(")
		return
	}

	//lookup user by email
	user, err := cfg.DB.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not find the user with this email :(")
		return
	}

	//compare the hashed password
	if err := auth.CheckPasswordHash(req.Password, user.HashedPasswords); err != nil {
		respondWithError(w, http.StatusBadRequest, "The password does not match :(")
		return
	}

	response := map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email,
		"created_at": user.CreatedAt,
		"updated_at": user.UpdatedAt,
	}

	writeJSON(w, http.StatusOK, response)
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

	//create sqlc queries instance
	dbQueries := database.New(db)

	//store in the apiConfig so the handlers can use it
	cfg := &apiConfig{
		DB:       dbQueries,
		PLATFORM: dbplatform,
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
	server := &http.Server{ // Create the server
		Addr:    ":8080",
		Handler: mux, // Bind to localhost:8080
	}

	log.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
