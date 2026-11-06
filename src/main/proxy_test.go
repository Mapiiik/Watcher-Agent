package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
)

const proxyHeader = "PROXY TCP4 203.0.113.7 192.0.2.1 5000 443\r\n"

// addressSeen makes one HTTPS request over a connection starting with the header and returns the address the
// server took the caller for. The caller itself is always 127.0.0.1.
func addressSeen(t *testing.T, allowCIDRs []string, header string) string {
	t.Helper()

	srv, err := buildHTTPServer(AppConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = io.WriteString(w, host)
	}))
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() { _ = srv.ServeTLS(newProxyListener(ln, allowCIDRs), "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	client := http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the server's own certificate
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if _, err := io.WriteString(conn, header); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}}
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return string(body)
}

func TestProxyHeaderFromAListedAddressIsUsed(t *testing.T) {
	if got := addressSeen(t, []string{"10.0.0.0/8", "127.0.0.0/8"}, proxyHeader); got != "203.0.113.7" {
		t.Errorf("address = %s", got)
	}
}

// The header stays optional there, as in our Caddy servers.
func TestProxyHeaderFromAListedAddressMayBeMissing(t *testing.T) {
	if got := addressSeen(t, []string{"127.0.0.0/8"}, ""); got != "127.0.0.1" {
		t.Errorf("address = %s", got)
	}
}

// The connection goes on with its real address, so a proxy left out of the list breaks less than a refusal would.
func TestProxyHeaderFromOutsideTheListIsIgnored(t *testing.T) {
	if got := addressSeen(t, []string{"10.0.0.0/8"}, proxyHeader); got != "127.0.0.1" {
		t.Errorf("address = %s", got)
	}
}

// An entry that is not a network matches nobody, the same as in AGENT_ROUTEROS_ALLOW_CIDRS.
func TestProxyHeaderWithABrokenEntryIsIgnored(t *testing.T) {
	if got := addressSeen(t, []string{"not-a-network"}, proxyHeader); got != "127.0.0.1" {
		t.Errorf("address = %s", got)
	}
}

// Installations running without the list keep working.
func TestProxyHeaderWithoutAListIsUsed(t *testing.T) {
	if got := addressSeen(t, nil, proxyHeader); got != "203.0.113.7" {
		t.Errorf("address = %s", got)
	}
}

func TestProxyListenerWarnsOnlyWithoutAList(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	newProxyListener(ln, []string{"10.0.0.0/8"})
	if logged.Len() != 0 {
		t.Errorf("warned with a list: %q", logged.String())
	}

	newProxyListener(ln, nil)
	if n := strings.Count(logged.String(), "AGENT_PROXY_ALLOW_CIDRS"); n != 1 {
		t.Errorf("%d warnings: %q", n, logged.String())
	}
}
