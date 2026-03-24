package main

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// Atomic flag to indicate server is draining (rejecting new requests)
var draining atomic.Bool

// Tracks active requests to allow graceful drainage
var activeRequests sync.WaitGroup

func drainMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track active request
		activeRequests.Add(1)
		defer activeRequests.Done()

		// Reject new requests during drain
		if draining.Load() {
			http.Error(w, "Server is shutting down", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
}
