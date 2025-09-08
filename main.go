package main

import (
	"log"
	"net/http"
)

func main() {
	const filepathRoot = "."
	const port = 8080
	mux := http.NewServeMux()

	mux.Handle("/", http.FileServer(http.Dir(filepathRoot))) // Serve static files from the root directory
	server := &http.Server{                                  // Create the server
		Addr:    ":8080", // Bind to localhost:8080
		Handler: mux,     // Use our ServeMux
	}

	log.Printf("Server files from %s on %d", filepathRoot, port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
