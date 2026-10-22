package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"watcher-agent/src/domain/radius"
)

func TestHandleDisconnectBadRequest(t *testing.T) {
	svc := NewRadiusService(radius.Config{Port: 3799, Timeout: time.Second})

	for name, body := range map[string]string{
		"not JSON":       "nas_ip=127.0.0.1",
		"without secret": `{"nas_ip":"127.0.0.1","username":"customer"}`,
		"without NAS":    `{"secret":"s","username":"customer"}`,
	} {
		rec := httptest.NewRecorder()
		svc.HandleDisconnect(rec, httptest.NewRequest("POST", "/api/radius/disconnect", jsonBody(body)))

		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "bad_request" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleDisconnectFailure(t *testing.T) {
	svc := NewRadiusService(radius.Config{Port: 3799, Timeout: time.Second})

	rec := httptest.NewRecorder()
	svc.HandleDisconnect(rec, httptest.NewRequest("POST", "/api/radius/disconnect",
		jsonBody(`{"nas_ip":"nas.invalid","secret":"s"}`)))

	if rec.Code != http.StatusInternalServerError || errorCode(t, rec) != "internal_error" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}
