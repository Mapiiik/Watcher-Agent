package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The ping itself needs a raw socket (CAP_NET_RAW), so only the answers before it are tested here.

func TestHandlePingBadRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	NewPingService().HandlePing(rec, httptest.NewRequest("POST", "/api/ping", jsonBody("host=192.0.2.1")))

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "bad_request" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePingUnresolvableHost(t *testing.T) {
	rec := httptest.NewRecorder()
	NewPingService().HandlePing(rec, httptest.NewRequest("POST", "/api/ping", jsonBody(`{"host":"cpe.invalid"}`)))

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "host_resolution_failed" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}
