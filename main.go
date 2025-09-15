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
	Email string `json:"email"`
}

// users handler
func (cfg *apiConfig) handlerUsers(w http.ResponseWriter, r *http.Request) {
	//parse json
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	//create user in db
	user, err := cfg.DB.CreateUser(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not create user")
		return
	}

	//respond
	writeJSON(w, http.StatusCreated, user)
}

// handle to delete all users
func (cfg *apiConfig) handleAdminReset(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /admin/resetUser", cfg.handleAdminReset)

	server := &http.Server{ // Create the server
		Addr:    ":8080",
		Handler: mux, // Bind to localhost:8080
	}

	log.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
