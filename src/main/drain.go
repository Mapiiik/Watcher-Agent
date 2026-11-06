package main

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// shutdownTimeout is how long running requests get to finish, under the stop_grace_period of 60 s in the compose files.
const shutdownTimeout = 50 * time.Second

// draining is set on shutdown, from then on new requests get 503
var draining atomic.Bool

func drainMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject new requests during drain
		if draining.Load() {
			http.Error(w, "Server is shutting down", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// shutdown rejects new requests and waits for the running ones, for at most the timeout.
func shutdown(timeout time.Duration, servers ...*http.Server) {
	draining.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Shutdown of the server on %s: %v", srv.Addr, err)
		}
	}
}
