package main

import (
	"log"
	"net/http"
)

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain ; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ok"))
}

func main() {
	mux := http.NewServeMux()

	//for index.html
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("."))))

	//for assets/logo.png
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))

	//for readiness endpoint
	mux.HandleFunc("/healthz", readinessHandler)

	server := &http.Server{ // Create the server
		Addr:    ":8080",
		Handler: mux, // Bind to localhost:8080
	}

	log.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
