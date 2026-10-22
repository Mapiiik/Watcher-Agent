package nms

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"watcher-agent/src/domain/snmp"
)

func client(url string) *NMSClient {
	return NewNMSClient(Config{BaseURL: url, Token: "nms-token", Timeout: time.Second})
}

func TestGetRouterOSProvisionScript(t *testing.T) {
	var got RouterOSProvisionRequest
	nms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent/provision/routeros.json" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if h := r.Header.Get("Authorization"); h != "Bearer nms-token" {
			t.Errorf("Authorization = %q", h)
		}
		if h := r.Header.Get("Content-Type"); h != "application/json" {
			t.Errorf("Content-Type = %q", h)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"script":"/system identity set name=customer-1"}`))
	}))
	defer nms.Close()

	script, err := client(nms.URL).GetRouterOSProvisionScript(RouterOSProvisionRequest{
		AgentID:    "agent-1",
		DeviceType: "router",
		Serial:     "HE408XYZ123",
		DeviceIP:   "100.64.1.2",
		SNMP:       snmp.SNMPReadResult{Device: snmp.SNMPDevice{Serial: "HE408XYZ123"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if script != "/system identity set name=customer-1" {
		t.Errorf("script = %q", script)
	}
	if got.AgentID != "agent-1" || got.DeviceType != "router" || got.Serial != "HE408XYZ123" ||
		got.DeviceIP != "100.64.1.2" || got.SNMP.Device.Serial != "HE408XYZ123" {
		t.Errorf("NMS got %+v", got)
	}
}

func TestGetRouterOSProvisionScriptNMSError(t *testing.T) {
	nms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown serial", http.StatusNotFound)
	}))
	defer nms.Close()

	_, err := client(nms.URL).GetRouterOSProvisionScript(RouterOSProvisionRequest{})
	if err == nil || !strings.Contains(err.Error(), "nms error 404: unknown serial") {
		t.Errorf("err = %v", err)
	}
}

func TestGetRouterOSProvisionScriptInvalidJSON(t *testing.T) {
	nms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	}))
	defer nms.Close()

	if _, err := client(nms.URL).GetRouterOSProvisionScript(RouterOSProvisionRequest{}); err == nil {
		t.Error("an HTML answer was taken for a script")
	}
}

func TestGetRouterOSProvisionScriptUnreachable(t *testing.T) {
	nms := httptest.NewServer(http.NotFoundHandler())
	url := nms.URL
	nms.Close()

	if _, err := client(url).GetRouterOSProvisionScript(RouterOSProvisionRequest{}); err == nil {
		t.Error("no error from a closed NMS")
	}
}
