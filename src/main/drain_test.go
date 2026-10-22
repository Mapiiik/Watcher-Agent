package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDrainMiddlewarePassesRequests(t *testing.T) {
	rec := httptest.NewRecorder()
	drainMiddleware(ok).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestDrainMiddlewareRejectsWhileDraining(t *testing.T) {
	draining.Store(true)
	t.Cleanup(func() { draining.Store(false) })

	called := false
	h := drainMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusServiceUnavailable || called {
		t.Errorf("status = %d, handler called %v", rec.Code, called)
	}
}

// Shutdown waits for activeRequests, so a request still running has to hold it.
func TestDrainMiddlewareCountsRunningRequests(t *testing.T) {
	release := make(chan struct{})
	h := drainMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))

	served := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		close(served)
	}()

	// Let the request get into the handler
	time.Sleep(20 * time.Millisecond)

	waited := make(chan struct{})
	go func() {
		activeRequests.Wait()
		close(waited)
	}()

	select {
	case <-waited:
		t.Fatal("Wait returned while a request was running")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-served
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after the request finished")
	}
}
