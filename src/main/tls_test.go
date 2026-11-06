package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"watcher-agent/src/domain/snmp"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if leaf.Subject.CommonName != "watcher-agent" || !slices.Equal(leaf.DNSNames, []string{"localhost"}) {
		t.Errorf("subject %q, DNS names %v", leaf.Subject.CommonName, leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP addresses = %v", leaf.IPAddresses)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("extended key usage = %v", leaf.ExtKeyUsage)
	}
	if key, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
		t.Errorf("key = %T", leaf.PublicKey)
	}
	if valid := time.Until(leaf.NotAfter); valid < 29*24*time.Hour || valid > 30*24*time.Hour {
		t.Errorf("valid for %v, want 30 days", valid)
	}
	if time.Now().Before(leaf.NotBefore) {
		t.Errorf("not valid yet (%v)", leaf.NotBefore)
	}
}

// TLS 1.2 is offered only with ECDHE and authenticated encryption.
func TestTLS12CipherSuitesAreECDHEWithAEAD(t *testing.T) {
	names := map[uint16]string{}
	for _, s := range tls.CipherSuites() {
		names[s.ID] = s.Name
	}

	for _, id := range tls12CipherSuites {
		name := names[id]
		aead := strings.Contains(name, "_GCM_") || strings.Contains(name, "CHACHA20_POLY1305")
		if !strings.HasPrefix(name, "TLS_ECDHE_") || !aead {
			t.Errorf("suite %#04x %q", id, name)
		}
	}
}

func TestBuildTLSConfigSelfSigned(t *testing.T) {
	cfg, err := buildTLSConfig(AppConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 || cfg.MinVersion != tls.VersionTLS12 || !slices.Equal(cfg.CipherSuites, tls12CipherSuites) {
		t.Errorf("certificates %d, min version %#x, suites %v", len(cfg.Certificates), cfg.MinVersion, cfg.CipherSuites)
	}
}

func TestBuildTLSConfigACME(t *testing.T) {
	cfg, err := buildTLSConfig(AppConfig{Hostname: "agent.example.net", CertDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetCertificate == nil || !slices.Contains(cfg.NextProtos, "acme-tls/1") {
		t.Errorf("not an ACME configuration: protocols %v", cfg.NextProtos)
	}
	if cfg.MinVersion != tls.VersionTLS12 || !slices.Equal(cfg.CipherSuites, tls12CipherSuites) {
		t.Errorf("min version %#x, suites %v", cfg.MinVersion, cfg.CipherSuites)
	}
}

func TestSelfSignedTLSHandshake(t *testing.T) {
	cfg, err := buildSelfSignedTLS()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				_ = conn.Close()
			}()
		}
	}()

	cases := []struct {
		name   string
		client *tls.Config
		ok     bool
	}{
		{"TLS 1.3", &tls.Config{}, true},
		{"TLS 1.2 with GCM", &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}, true},
		{"TLS 1.2 with CBC", &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}}, false},
		{"TLS 1.1", &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}, false},
	}

	for _, c := range cases {
		c.client.InsecureSkipVerify = true //nolint:gosec // the certificate is self-signed on purpose
		conn, err := tls.Dial("tcp", ln.Addr().String(), c.client)
		if err == nil {
			_ = conn.Close()
		}
		if (err == nil) != c.ok {
			t.Errorf("%s: handshake error %v, want success %v", c.name, err, c.ok)
		}
	}
}

func TestServersHaveTimeouts(t *testing.T) {
	https, err := buildHTTPServer(AppConfig{}, ok)
	if err != nil {
		t.Fatal(err)
	}

	for name, srv := range map[string]*http.Server{"HTTP": newServer("", ok), "HTTPS": https} {
		if srv.ReadHeaderTimeout != 30*time.Second || srv.ReadTimeout != 30*time.Second || srv.IdleTimeout != 120*time.Second {
			t.Errorf("%s: header %v, read %v, idle %v", name, srv.ReadHeaderTimeout, srv.ReadTimeout, srv.IdleTimeout)
		}
		// Provisioning: the serial check, a full read and the call to the NMS, the NMS itself waits 120 s
		if longest := 9*time.Second + snmp.ReadTimeLimit + 10*time.Second; srv.WriteTimeout <= longest || srv.WriteTimeout < 120*time.Second {
			t.Errorf("%s: write %v, the longest request takes %v", name, srv.WriteTimeout, longest)
		}
	}
}

// A handler runs long after its request has been read, an SNMP read does.
func TestRequestOutlastsReadTimeout(t *testing.T) {
	for protocol, want := range map[string]string{"http/1.1": "HTTP/1.1", "h2": "HTTP/2.0"} {
		srv, err := buildHTTPServer(AppConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			_, _ = io.WriteString(w, r.Proto)
		}))
		if err != nil {
			t.Fatal(err)
		}
		srv.ReadHeaderTimeout = 50 * time.Millisecond
		srv.ReadTimeout = 50 * time.Millisecond

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.ServeTLS(newProxyListener(ln, []string{"127.0.0.0/8"}), "", "") }()
		t.Cleanup(func() { _ = srv.Close() })

		client := http.Client{Transport: &http.Transport{
			ForceAttemptHTTP2: protocol == "h2",
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // the server's own certificate
				NextProtos:         []string{protocol},
			},
		}}
		defer client.CloseIdleConnections()

		resp, err := client.Get("https://" + ln.Addr().String() + "/")
		if err != nil {
			t.Fatalf("%s: %v", protocol, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || string(body) != want {
			t.Errorf("%s: %d %q %v", protocol, resp.StatusCode, body, err)
		}
	}
}
