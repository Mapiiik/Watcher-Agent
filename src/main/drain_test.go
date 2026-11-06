package main

import (
	"net"
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

// serveBlocked starts a server whose handler stays in a request until released, and sends it one request. It returns
// once the handler is running; the status of the answer comes on the channel.
func serveBlocked(t *testing.T) (srv *http.Server, release chan struct{}, status chan int) {
	t.Helper()

	release = make(chan struct{})
	running := make(chan struct{})
	srv = newServer("", drainMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(running)
		<-release
	})))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		draining.Store(false)
		_ = srv.Close()
	})

	status = make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			status <- 0
			return
		}
		_ = resp.Body.Close()
		status <- resp.StatusCode
	}()

	<-running

	return srv, release, status
}

func TestShutdownWaitsForARunningRequest(t *testing.T) {
	srv, release, status := serveBlocked(t)

	stopped := make(chan struct{})
	go func() {
		shutdown(5*time.Second, srv)
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("shutdown returned while a request was running")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	if got := <-status; got != http.StatusOK {
		t.Errorf("status = %d", got)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not return after the request finished")
	}
}

// A request that does not end must not keep the agent from stopping.
func TestShutdownGivesUpAtTheTimeout(t *testing.T) {
	srv, release, _ := serveBlocked(t)
	t.Cleanup(func() { close(release) })

	stopped := make(chan struct{})
	go func() {
		shutdown(100*time.Millisecond, srv)
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not give up")
	}
}

// Requests in progress get as long as Docker leaves the process.
func TestShutdownTimeoutFitsTheComposeFiles(t *testing.T) {
	if shutdownTimeout < 30*time.Second || shutdownTimeout >= 60*time.Second {
		t.Errorf("shutdown timeout = %v, the compose files give 60 s", shutdownTimeout)
	}
}
