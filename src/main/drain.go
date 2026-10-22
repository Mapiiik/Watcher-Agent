package main

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// draining is set on shutdown, from then on new requests get 503
var draining atomic.Bool

// activeRequests counts the requests in progress, shutdown waits for them
var activeRequests sync.WaitGroup

func drainMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
