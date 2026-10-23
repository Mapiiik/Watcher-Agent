package routeros

import (
	"bytes"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"watcher-agent/src/testutil/routerosapi"
)

const (
	testUser     = "watcher-agent"
	testPassword = "s3cret"
)

var testMenus = map[string][]map[string]string{"/ip/firewall/address-list": nil}

func testConfig(tlsPort, plainPort int) Config {
	return Config{
		Username:  testUser,
		Password:  testPassword,
		Timeout:   2 * time.Second,
		TLSPort:   tlsPort,
		PlainPort: plainPort,
	}
}

func plainRouter(t *testing.T) *routerosapi.Server {
	return routerosapi.Start(t, routerosapi.Options{Username: testUser, Password: testPassword, Menus: testMenus})
}

func tlsRouter(t *testing.T, cert tls.Certificate, menus map[string][]map[string]string) *routerosapi.Server {
	return routerosapi.Start(t, routerosapi.Options{
		Username: testUser,
		Password: testPassword,
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
		Menus:    menus,
	})
}

// closedPort refuses connections, like a router with api-ssl switched off.
func closedPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// noCertificatePort answers the handshake with a handshake_failure alert, as RouterOS does without a certificate:
// it then offers only anonymous DH, which the agent does not.
func noCertificatePort(t *testing.T) int {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{routerosapi.SelfSigned(t)},
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// silentPort accepts and never answers, like a port somebody in between holds open.
func silentPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// captureLog collects what the package logs during the test.
func captureLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestOpenOverTLSWithoutVerifying(t *testing.T) {
	router := tlsRouter(t, routerosapi.SelfSigned(t), testMenus)

	s, err := Open(testConfig(router.Port, closedPort(t)), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	if s.Transport != TransportTLS {
		t.Errorf("transport = %s", s.Transport)
	}
	if _, err := s.Run("/ip/firewall/address-list/print"); err != nil {
		t.Errorf("print: %v", err)
	}
}

func TestOpenFallsBackToPlainAPI(t *testing.T) {
	for name, tc := range map[string]struct {
		tlsPort func(*testing.T) int
		reason  string
	}{
		"api-ssl refused":     {closedPort, "plain api (api-ssl refused)"},
		"without certificate": {noCertificatePort, "plain api (no certificate for api-ssl)"},
	} {
		t.Run(name, func(t *testing.T) {
			logged := captureLog(t)
			router := plainRouter(t)
			cfg := testConfig(tc.tlsPort(t), router.Port)
			cfg.PlainFallback = true

			s, err := Open(cfg, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()

			if s.Transport != TransportPlain {
				t.Errorf("transport = %s", s.Transport)
			}
			if !strings.Contains(logged.String(), "RouterOS API 127.0.0.1: "+tc.reason) {
				t.Errorf("log = %q", logged.String())
			}
		})
	}
}

// Nothing else is a reason to send the password unencrypted: not the fallback switched off, not a timeout that may
// be somebody in between, not a refused login, which would only hide a wrong password.
func TestOpenStaysOffThePlainAPI(t *testing.T) {
	for name, tc := range map[string]struct {
		tlsPort  func(*testing.T) int
		fallback bool
		password string
		want     error
	}{
		"fallback switched off": {closedPort, false, testPassword, ErrUnreachable},
		"api-ssl times out":     {silentPort, true, testPassword, ErrUnreachable},
		"login refused over TLS": {
			func(t *testing.T) int { return tlsRouter(t, routerosapi.SelfSigned(t), testMenus).Port },
			true, "wrong", ErrLoginFailed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			plain := plainRouter(t)
			cfg := testConfig(tc.tlsPort(t), plain.Port)
			cfg.PlainFallback = tc.fallback
			cfg.Password = tc.password
			cfg.Timeout = 300 * time.Millisecond

			if _, err := Open(cfg, "127.0.0.1"); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if n := plain.Connections(); n != 0 {
				t.Errorf("%d connections to the plain api", n)
			}
		})
	}
}

func TestOpenVerifiesAgainstTheCA(t *testing.T) {
	ca := routerosapi.NewCA(t)
	foreign := routerosapi.NewCA(t)

	withoutCA := ca.Leaf(t, time.Now().Add(time.Hour))
	withoutCA.Certificate = withoutCA.Certificate[:1]

	for name, tc := range map[string]struct {
		cert tls.Certificate
		ok   bool
	}{
		// the certificate names no address, so this also shows that 127.0.0.1 is not checked
		"signed by the CA":    {ca.Leaf(t, time.Now().Add(time.Hour)), true},
		"self-signed":         {routerosapi.SelfSigned(t), false},
		"another CA":          {foreign.Leaf(t, time.Now().Add(time.Hour)), false},
		"expired":             {ca.Leaf(t, time.Now().Add(-time.Hour)), false},
		"CA not in the chain": {withoutCA, false},
	} {
		t.Run(name, func(t *testing.T) {
			router := tlsRouter(t, tc.cert, testMenus)
			plain := plainRouter(t)
			cfg := testConfig(router.Port, plain.Port)
			cfg.CAFingerprint = ca.Fingerprint()
			cfg.PlainFallback = true

			s, err := Open(cfg, "127.0.0.1")
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				_ = s.Close()
				return
			}

			if !errors.Is(err, ErrCertificateInvalid) {
				t.Errorf("err = %v", err)
			}
			if n := plain.Connections(); n != 0 {
				t.Errorf("%d connections to the plain api", n)
			}
		})
	}
}

func TestRunReportsATrap(t *testing.T) {
	router := tlsRouter(t, routerosapi.SelfSigned(t), testMenus)
	s, err := Open(testConfig(router.Port, 0), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	_, err = s.Run("/system/nonsense/print")
	if !errors.Is(err, ErrCommandFailed) || !strings.Contains(err.Error(), "/system/nonsense/print: no such command prefix") {
		t.Errorf("err = %v", err)
	}
}
