package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux() // Create a new ServeMux

	server := &http.Server{ // Create the server
		Addr:    ":8080", // Bind to localhost:8080
		Handler: mux,     // Use our ServeMux
	}

	log.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
