package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
	h := bearerAuth(AppConfig{APIToken: "api-token"}, ok)

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
