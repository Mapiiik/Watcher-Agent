package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/testutil/snmpagent"
)

func TestHandleRouterOSRead(t *testing.T) {
	a := snmpagent.Start(t, "c0mmunity", snmpagent.MinimalRouterOS("HE408XYZ123"))
	svc := NewSNMPService(snmp.Config{Port: a.Port, Timeout: 500 * time.Millisecond})

	rec := httptest.NewRecorder()
	svc.HandleRouterOSRead(rec, httptest.NewRequest("POST", "/api/snmp/read/routeros",
		jsonBody(`{"host":"127.0.0.1","community":"c0mmunity"}`)))

	var res snmp.SNMPReadResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusOK || res.Device.Serial != "HE408XYZ123" || len(res.Interfaces) != 1 || len(res.IPAddresses) != 1 {
		t.Errorf("%d %+v", rec.Code, res)
	}
}

func TestHandleRouterOSReadBadRequest(t *testing.T) {
	svc := NewSNMPService(snmp.Config{})

	for name, body := range map[string]string{
		"not JSON":          "host=127.0.0.1",
		"without community": `{"host":"127.0.0.1"}`,
		"without host":      `{"community":"public"}`,
	} {
		rec := httptest.NewRecorder()
		svc.HandleRouterOSRead(rec, httptest.NewRequest("POST", "/api/snmp/read/routeros", jsonBody(body)))

		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "bad_request" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleRouterOSReadUnreachable(t *testing.T) {
	svc := NewSNMPService(closedSNMP(t))

	rec := httptest.NewRecorder()
	svc.HandleRouterOSRead(rec, httptest.NewRequest("POST", "/api/snmp/read/routeros",
		jsonBody(`{"host":"127.0.0.1","community":"public"}`)))

	if rec.Code != http.StatusBadGateway || errorCode(t, rec) != "snmp_read_failed" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}
