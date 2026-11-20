package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"watcher-agent/src/httphelpers"
)

var ok = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
})

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not a JSON error: %q", rec.Body.String())
	}
	return body["error"]
}

func TestBearerAuth(t *testing.T) {
	h := bearerAuth(AppConfig{APIAccess: []APIAccess{{Name: "default", Token: "api-token"}}}, ok)

	for header, want := range map[string]int{
		"Bearer api-token":    http.StatusNoContent,
		"Bearer  api-token  ": http.StatusNoContent,
		"":                    http.StatusUnauthorized,
		"Bearer ":             http.StatusUnauthorized,
		"Bearer api-token2":   http.StatusUnauthorized,
		"Bearer api-toke":     http.StatusUnauthorized,
		"bearer api-token":    http.StatusUnauthorized,
		"Basic api-token":     http.StatusUnauthorized,
		"api-token":           http.StatusUnauthorized,
	} {
		r := httptest.NewRequest("GET", "/api/status", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)

		if rec.Code != want {
			t.Errorf("Authorization %q: status %d, want %d", header, rec.Code, want)
		}
		if want == http.StatusUnauthorized && errorCode(t, rec) != "unauthorized" {
			t.Errorf("Authorization %q: %s", header, rec.Body.String())
		}
	}
}

// A caller of the API gets its body read up to the bound and no further.
func TestBearerAuthBoundsTheBody(t *testing.T) {
	var read int
	var readErr error
	h := bearerAuth(AppConfig{APIAccess: []APIAccess{{Name: "default", Token: "api-token"}}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b []byte
		b, readErr = io.ReadAll(r.Body)
		read = len(b)
	}))

	for size, fits := range map[int]bool{maxBodyBytes: true, maxBodyBytes + 1: false} {
		r := httptest.NewRequest("POST", "/api/routeros/address-list/sync", strings.NewReader(strings.Repeat("x", size)))
		r.Header.Set("Authorization", "Bearer api-token")
		h.ServeHTTP(httptest.NewRecorder(), r)

		var tooLarge *http.MaxBytesError
		if fits && (readErr != nil || read != size) || !fits && !errors.As(readErr, &tooLarge) {
			t.Errorf("%d bytes: read %d, %v", size, read, readErr)
		}
	}
}

func TestIPAllowed(t *testing.T) {
	cidrs := []string{"10.0.0.0/8", "not-a-cidr", "2a02:3c0::/29"}

	for ip, want := range map[string]bool{
		"10.1.2.3":         true,
		"11.0.0.1":         false,
		"2a02:3c0:cc00::1": true,
		"2001:db8::1":      false,
		"not-an-ip":        false,
		"":                 false,
	} {
		if got := ipAllowed(ip, cidrs); got != want {
			t.Errorf("ipAllowed(%q) = %v, want %v", ip, got, want)
		}
	}
}

// The default AGENT_ROUTEROS_ALLOW_CIDRS (0.0.0.0/0) lets in every IPv4 address and no IPv6 one.
func TestIPAllowedDefaultIsIPv4Only(t *testing.T) {
	if !ipAllowed("198.51.100.7", []string{"0.0.0.0/0"}) || ipAllowed("2001:db8::1", []string{"0.0.0.0/0"}) {
		t.Error("0.0.0.0/0 is expected to cover IPv4 only")
	}
}

func TestRouterOSGuard(t *testing.T) {
	open := routerOSGuard(AppConfig{RouterOSAllowCIDRs: []string{"10.0.0.0/8"}}, ok)
	withToken := routerOSGuard(AppConfig{RouterOSAllowCIDRs: []string{"10.0.0.0/8"}, RouterOSQueryToken: "q-token"}, ok)

	cases := []struct {
		name   string
		h      http.Handler
		remote string
		query  string
		want   int
	}{
		{"allowed address", open, "10.1.2.3:40000", "", http.StatusNoContent},
		{"address without port", open, "10.1.2.3", "", http.StatusNoContent},
		{"other address", open, "192.0.2.1:40000", "", http.StatusForbidden},
		{"query token", withToken, "10.1.2.3:40000", "?token=q-token", http.StatusNoContent},
		{"no query token", withToken, "10.1.2.3:40000", "", http.StatusForbidden},
		{"wrong query token", withToken, "10.1.2.3:40000", "?token=other", http.StatusForbidden},
		{"query token from another address", withToken, "192.0.2.1:40000", "?token=q-token", http.StatusForbidden},
	}

	for _, c := range cases {
		r := httptest.NewRequest("GET", "/provision/routeros/router/HE408"+c.query, nil)
		r.RemoteAddr = c.remote
		rec := httptest.NewRecorder()
		c.h.ServeHTTP(rec, r)

		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
		if c.want == http.StatusForbidden && errorCode(t, rec) != "forbidden" {
			t.Errorf("%s: %s", c.name, rec.Body.String())
		}
	}
}

// Refusals are logged with the caller, the guessed token and query token are not.
func TestRefusalsAreLogged(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	r := httptest.NewRequest("GET", "/api/status", nil)
	r.Header.Set("Authorization", "Bearer guessed-token")
	bearerAuth(AppConfig{APIAccess: []APIAccess{{Name: "default", Token: "api-token"}}}, ok).ServeHTTP(httptest.NewRecorder(), r)

	guard := routerOSGuard(AppConfig{RouterOSAllowCIDRs: []string{"10.0.0.0/8"}, RouterOSQueryToken: "q-token"}, ok)
	r = httptest.NewRequest("GET", "/provision/routeros/router/HE408?token=guessed-query", nil)
	r.RemoteAddr = "10.1.2.3:4000"
	guard.ServeHTTP(httptest.NewRecorder(), r)
	guard.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/provision/routeros/router/HE408", nil))

	for _, line := range []string{
		`WARN API request refused client=192.0.2.1 path=/api/status reason="invalid or missing token"`,
		`WARN provisioning refused client=10.1.2.3 path=/provision/routeros/router/HE408 reason="invalid or missing query token"`,
		`WARN provisioning refused client=192.0.2.1 path=/provision/routeros/router/HE408 reason="address not allowed"`,
	} {
		if !strings.Contains(logged.String(), line) {
			t.Errorf("the log lacks %q in %q", line, logged.String())
		}
	}
	for _, secret := range []string{"guessed-token", "guessed-query"} {
		if strings.Contains(logged.String(), secret) {
			t.Errorf("the log holds %q", secret)
		}
	}
}

// Each access is let in with its own key and named in the request; a key shared is named by the first with it.
func TestTheAccessOfAKeyIsNamed(t *testing.T) {
	cfg := AppConfig{APIAccess: []APIAccess{
		{Name: "crm", Token: "shared-key"}, {Name: "nms", Token: "shared-key"}, {Name: "watcher", Token: "own-key"},
	}}
	var caller string
	h := bearerAuth(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller = httphelpers.Caller(r)
	}))

	for token, want := range map[string]string{"shared-key": "crm", "own-key": "watcher", "other-key": ""} {
		caller = ""
		r := httptest.NewRequest("GET", "/api/status", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if caller != want || (want == "") != (rec.Code == http.StatusUnauthorized) {
			t.Errorf("%s: caller %q, status %d", token, caller, rec.Code)
		}
	}
}
