package httpapi

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"watcher-agent/src/domain/snmp"
)

// errorCode is the "error" field of a JSON error answer.
func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not a JSON error: %q", rec.Body.String())
	}
	return body["error"]
}

// closedSNMP is an SNMP configuration pointing at a local port nobody answers on.
func closedSNMP(t *testing.T) snmp.Config {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return snmp.Config{Port: uint16(port), Timeout: 50 * time.Millisecond} //nolint:gosec // a UDP port fits
}

func TestRemoteIP(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.10:51234":    "192.0.2.10",
		"[2001:db8::1]:51234": "2001:db8::1",
		"192.0.2.10":          "192.0.2.10",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		if got := remoteIP(r); got != want {
			t.Errorf("remoteIP(%q) = %q, want %q", addr, got, want)
		}
	}
}

func jsonBody(s string) *strings.Reader {
	return strings.NewReader(s)
}
