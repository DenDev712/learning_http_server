package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

// handler for readiness
func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain ; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ok"))
}

// will be used to increment safely across multiple goroutines
type apiConfig struct {
	fileserverHits atomic.Int32
}

// middleware to increment the counter
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// metrcs handler to show the hits
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "test/plain ; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hits: %d\n", cfg.fileserverHits.Load())
}

// reest handler to reset the counter
func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain ; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}
func main() {
	cfg := &apiConfig{} //holds the counter
	mux := http.NewServeMux()

	//for index.html
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	//for assets/logo.png
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))

	//for readiness endpoint
	mux.HandleFunc("GET /api/healthz", readinessHandler)

	//metrics endpoint
	mux.HandleFunc("GET /api/metrics", cfg.metricsHandler)

	//reset endpoint
	mux.HandleFunc("POST /api/reset", cfg.resetHandler)

	server := &http.Server{ // Create the server
		Addr:    ":8080",
		Handler: mux, // Bind to localhost:8080
	}

	log.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
