package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHandleRoot(t *testing.T) {
	rec := httptest.NewRecorder()
	NewRootService("agent-7").HandleRoot(rec, httptest.NewRequest("GET", "/", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || body["status"] != "ok" || body["agent_id"] != "agent-7" || body["service"] != "watcher-agent" {
		t.Errorf("%d %v", rec.Code, body)
	}
}

// The root handler is the mux fallback, so every unknown path ends here.
func TestHandleRootUnknownPath(t *testing.T) {
	rec := httptest.NewRecorder()
	NewRootService("agent-7").HandleRoot(rec, httptest.NewRequest("GET", "/wp-login.php", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHandleStatus(t *testing.T) {
	svc := NewStatusService("agent-7", map[string]DeviceTypeConfig{"router": {Community: "secret"}})
	svc.startTime = time.Now().Add(-90 * time.Second)

	rec := httptest.NewRecorder()
	svc.HandleStatus(rec, httptest.NewRequest("GET", "/api/status", nil))

	var body struct {
		Status        string `json:"status"`
		AgentID       string `json:"agent_id"`
		StartedAt     string `json:"started_at"`
		Uptime        string `json:"uptime"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		Capabilities  struct {
			DeviceTypes []string `json:"device_types"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	if body.Status != "ok" || body.AgentID != "agent-7" || body.Uptime != "1m 30s" || body.UptimeSeconds != 90 {
		t.Errorf("status = %+v", body)
	}
	if _, err := time.Parse(time.RFC3339, body.StartedAt); err != nil {
		t.Errorf("started_at %q: %v", body.StartedAt, err)
	}
	if !slices.Equal(body.Capabilities.DeviceTypes, []string{"router"}) {
		t.Errorf("device types = %v", body.Capabilities.DeviceTypes)
	}
}

func TestHandleStatusNamesTheDeviceTypesOnly(t *testing.T) {
	rec := httptest.NewRecorder()
	NewStatusService("agent-7", map[string]DeviceTypeConfig{
		"router": {Community: "router-community"},
		"bridge": {Community: "bridge-community"},
	}).HandleStatus(rec, httptest.NewRequest("GET", "/api/status", nil))

	if want := `"device_types":["bridge","router"]`; !strings.Contains(rec.Body.String(), want) {
		t.Errorf("%s, want %s", rec.Body.String(), want)
	}
	if strings.Contains(rec.Body.String(), "community") {
		t.Errorf("the answer gives a community away: %s", rec.Body.String())
	}
}

func TestHandleStatusWithoutDeviceTypes(t *testing.T) {
	rec := httptest.NewRecorder()
	NewStatusService("agent-7", nil).HandleStatus(rec, httptest.NewRequest("GET", "/api/status", nil))

	if want := `"device_types":[]`; !strings.Contains(rec.Body.String(), want) {
		t.Errorf("%s, want %s", rec.Body.String(), want)
	}
}

func TestFormatUptime(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                "0s",
		59 * time.Second: "59s",
		61 * time.Second: "1m 1s",
		3*time.Hour + 7*time.Minute + 9*time.Second: "3h 7m",
		50 * time.Hour: "50h 0m",
	} {
		if got := formatUptime(d); got != want {
			t.Errorf("formatUptime(%v) = %q, want %q", d, got, want)
		}
	}
}
