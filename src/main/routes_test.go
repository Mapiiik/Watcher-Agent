package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"watcher-agent/src/domain/radius"
	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/integration/nms"
)

func handler() http.Handler {
	return newHandler(
		AppConfig{APIToken: "api-token", AgentID: "agent-7", RouterOSAllowCIDRs: []string{"10.0.0.0/8"}},
		radius.Config{Port: 3799, Timeout: time.Second},
		snmp.Config{Port: 161, Timeout: 50 * time.Millisecond},
		nms.Config{BaseURL: "http://127.0.0.1:1", Token: "nms-token", Timeout: time.Second},
	)
}

func serve(h http.Handler, method, path, token, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader("{"))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if remote != "" {
		r.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestEndpointsNeedTheToken(t *testing.T) {
	h := handler()

	for _, path := range []string{"/api/status", "/api/ping", "/api/radius/disconnect", "/api/snmp/read/routeros"} {
		if rec := serve(h, "POST", path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d", path, rec.Code)
		}
		if rec := serve(h, "POST", path, "wrong", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with a wrong token: %d", path, rec.Code)
		}
	}

	if rec := serve(h, "GET", "/api/status", "api-token", ""); rec.Code != http.StatusOK {
		t.Errorf("/api/status with the token: %d", rec.Code)
	}
	// The body "{" is not JSON, so reaching the handler means 400
	for _, path := range []string{"/api/ping", "/api/radius/disconnect", "/api/snmp/read/routeros"} {
		if rec := serve(h, "POST", path, "api-token", ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%s with the token: %d, want the handler's 400", path, rec.Code)
		}
	}
}

func TestRootNeedsNoToken(t *testing.T) {
	h := handler()

	if rec := serve(h, "GET", "/", "", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"agent_id":"agent-7"`) {
		t.Errorf("/: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(h, "GET", "/api/unknown", "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("/api/unknown: %d", rec.Code)
	}
}

func TestProvisioningNeedsAnAllowedAddress(t *testing.T) {
	h := handler()

	if rec := serve(h, "GET", "/provision/routeros/router/HE408", "", "192.0.2.1:40000"); rec.Code != http.StatusForbidden {
		t.Errorf("from outside the list: %d", rec.Code)
	}
	// The API token does not open provisioning from elsewhere
	if rec := serve(h, "GET", "/provision/routeros/router/HE408", "api-token", "192.0.2.1:40000"); rec.Code != http.StatusForbidden {
		t.Errorf("with the API token from outside the list: %d", rec.Code)
	}

	rec := serve(h, "GET", "/provision/routeros/router/HE408", "", "10.1.2.3:40000")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), ":log error \"Watcher Agent: Unknown device type") {
		t.Errorf("from the list: %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandlerRejectsWhileDraining(t *testing.T) {
	draining.Store(true)
	t.Cleanup(func() { draining.Store(false) })

	if rec := serve(handler(), "GET", "/", "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestHTTPSRedirect(t *testing.T) {
	cases := []struct {
		listen, host, target, want string
	}{
		{"0.0.0.0:443", "agent.example.net", "/api/status?x=1", "https://agent.example.net:443/api/status?x=1"},
		{"0.0.0.0:443", "agent.example.net:80", "/", "https://agent.example.net:443/"},
		{":8443", "192.0.2.10:8080", "/provision/routeros/router/HE408", "https://192.0.2.10:8443/provision/routeros/router/HE408"},
		{"[::]:443", "[2001:db8::1]:80", "/", "https://[2001:db8::1]:443/"},
		{"[::]:443", "[2001:db8::1]", "/", "https://[2001:db8::1]:443/"},
	}

	for _, c := range cases {
		r := httptest.NewRequest("GET", c.target, nil)
		r.Host = c.host
		rec := httptest.NewRecorder()
		httpsRedirect(c.listen).ServeHTTP(rec, r)

		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != c.want {
			t.Errorf("%s via %s: %d %q, want %q", c.host, c.listen, rec.Code, rec.Header().Get("Location"), c.want)
		}
	}
}

func TestHTTPSRedirectBadListenAddress(t *testing.T) {
	rec := httptest.NewRecorder()
	httpsRedirect("443").ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d", rec.Code)
	}
}
