package main

import (
	"log"
	"net/http"
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`{"service":"watcher-agent","status":"ok"}`))
	if err != nil {
		log.Printf("Failed to write HTTP response: %v", err)
	}
}
