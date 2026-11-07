package main

import (
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// servers builds the two servers of the agent, HTTPS on the given address.
func servers(t *testing.T, httpsAddr string) (cfg AppConfig, srvHTTP, srvHTTPS *http.Server) {
	t.Helper()

	cfg = AppConfig{ListenHttp: "127.0.0.1:0", ListenHttps: httpsAddr}

	srvHTTPS, err := buildHTTPServer(cfg, ok)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { draining.Store(false) })

	return cfg, newServer(cfg.ListenHttp, ok), srvHTTPS
}

func waitFor(t *testing.T, stopped <-chan error) error {
	t.Helper()

	select {
	case err := <-stopped:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("still running")
		return nil
	}
}

// Without HTTPS the agent only redirects to something that is not there.
func TestRunEndsWithHTTPS(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = taken.Close() })

	for name, useProxyProtocol := range map[string]bool{"PROXY protocol": true, "plain": false} {
		cfg, srvHTTP, srvHTTPS := servers(t, taken.Addr().String())
		cfg.UseProxyProtocol = useProxyProtocol

		stopped := make(chan error, 1)
		go func() { stopped <- run(cfg, srvHTTP, srvHTTPS, make(chan os.Signal)) }()

		if err := waitFor(t, stopped); err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRunEndsWithoutAnErrorOnASignal(t *testing.T) {
	cfg, srvHTTP, srvHTTPS := servers(t, "127.0.0.1:0")

	signals := make(chan os.Signal, 1)
	stopped := make(chan error, 1)
	go func() { stopped <- run(cfg, srvHTTP, srvHTTPS, signals) }()

	signals <- syscall.SIGTERM

	if err := waitFor(t, stopped); err != nil {
		t.Errorf("err = %v", err)
	}
}
