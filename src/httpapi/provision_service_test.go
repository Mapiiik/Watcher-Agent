package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/integration/nms"
	"watcher-agent/src/testutil/snmpagent"
)

const provisionCommunity = "pr0vision"

type provisionSetup struct {
	svc *ProvisionService
	// What the NMS was asked, empty when it was not
	asked chan nms.RouterOSProvisionRequest
}

// newProvision runs the device (at 127.0.0.1, where the requests come from) and an NMS that answers with
// nmsStatus and nmsBody.
func newProvision(t *testing.T, snmpCfg snmp.Config, nmsStatus int, nmsBody string) provisionSetup {
	t.Helper()

	asked := make(chan nms.RouterOSProvisionRequest, 1)
	nmsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req nms.RouterOSProvisionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		asked <- req
		w.WriteHeader(nmsStatus)
		_, _ = w.Write([]byte(nmsBody))
	}))
	t.Cleanup(nmsServer.Close)

	cfg := ProvisionConfig{
		AgentID: "agent-7",
		DeviceTypes: map[string]DeviceTypeConfig{
			"router": {Community: provisionCommunity},
			"blank":  {Community: " "},
		},
	}
	client := nms.NewNMSClient(nms.Config{BaseURL: nmsServer.URL, Token: "t", Timeout: time.Second})

	return provisionSetup{svc: NewProvisionService(cfg, snmpCfg, client), asked: asked}
}

func device(t *testing.T, serial string) snmp.Config {
	a := snmpagent.Start(t, provisionCommunity, snmpagent.MinimalRouterOS(serial))
	return snmp.Config{Port: a.Port, Timeout: 500 * time.Millisecond}
}

func (p provisionSetup) get(path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "127.0.0.1:40123"
	rec := httptest.NewRecorder()
	p.svc.HandleRouterOS(rec, r)
	return rec
}

func TestHandleRouterOS(t *testing.T) {
	p := newProvision(t, device(t, "HE408XYZ123"), http.StatusOK, `{"script":"/system identity set name=customer-1"}`)

	rec := p.get("/provision/routeros/router/HE408XYZ123")

	if rec.Body.String() != "/system identity set name=customer-1" || rec.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("%q %q", rec.Header().Get("Content-Type"), rec.Body.String())
	}

	req := <-p.asked
	if req.AgentID != "agent-7" || req.DeviceType != "router" || req.Serial != "HE408XYZ123" || req.DeviceIP != "127.0.0.1" {
		t.Errorf("NMS asked %+v", req)
	}
	if req.SNMP.Device.Serial != "HE408XYZ123" || len(req.SNMP.Interfaces) != 1 {
		t.Errorf("NMS got SNMP %+v", req.SNMP)
	}
}

// Every failure answers with a RouterOS script that only logs, so the device never runs anything else.
func TestHandleRouterOSFailures(t *testing.T) {
	cases := []struct {
		name      string
		snmp      snmp.Config
		nmsStatus int
		path      string
		want      string
	}{
		{"short URL", closedSNMP(t), http.StatusOK, "/provision/routeros/router", "Invalid provisioning URL"},
		{"long URL", closedSNMP(t), http.StatusOK, "/provision/routeros/router/HE408XYZ123/x", "Invalid provisioning URL"},
		{"unknown type", closedSNMP(t), http.StatusOK, "/provision/routeros/switch/HE408XYZ123", "Unknown device type or missing community (switch)"},
		{"blank community", closedSNMP(t), http.StatusOK, "/provision/routeros/blank/HE408XYZ123", "Unknown device type or missing community (blank)"},
		{"no answer", closedSNMP(t), http.StatusOK, "/provision/routeros/router/HE408XYZ123", "SNMP serial read failed: "},
		{"other serial", device(t, "HE408XYZ123"), http.StatusOK, "/provision/routeros/router/HE999", "Serial mismatch (got HE408XYZ123, expected HE999)"},
		{"NMS error", device(t, "HE408XYZ123"), http.StatusInternalServerError, "/provision/routeros/router/HE408XYZ123", "NMS provision failed: nms error 500: "},
	}

	for _, c := range cases {
		p := newProvision(t, c.snmp, c.nmsStatus, `{"message":"down"}`)
		rec := p.get(c.path)

		body := rec.Body.String()
		prefix := ":log error \"Watcher Agent: "
		if !strings.HasPrefix(body, prefix+c.want) || !strings.HasSuffix(body, "\"\n") || strings.Count(body, "\n") != 1 {
			t.Errorf("%s: %q, want %q", c.name, body, prefix+c.want+"…")
		}
		if rec.Header().Get("Content-Type") != "text/plain" {
			t.Errorf("%s: Content-Type %q", c.name, rec.Header().Get("Content-Type"))
		}
	}
}
