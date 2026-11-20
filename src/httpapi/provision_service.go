package httpapi

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/httphelpers"
	"watcher-agent/src/integration/nms"
)

type ProvisionService struct {
	cfg     ProvisionConfig
	snmpCfg snmp.Config
	nms     *nms.NMSClient
}

func NewProvisionService(
	cfg ProvisionConfig,
	snmpCfg snmp.Config,
	nmsClient *nms.NMSClient,
) *ProvisionService {
	return &ProvisionService{
		cfg:     cfg,
		snmpCfg: snmpCfg,
		nms:     nmsClient,
	}
}

// HandleRouterOS answers GET /provision/routeros/{deviceType}/{serial} from the device itself: it checks the
// serial over SNMP at the caller's address, sends the full read to the NMS and returns the NMS script. Every
// failure is answered with a script that only logs it.
func (s *ProvisionService) HandleRouterOS(w http.ResponseWriter, r *http.Request) {
	host := remoteIP(r)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		slog.Warn("provisioning refused", "device", host, "reason", "Invalid provisioning URL")
		httphelpers.WriteRouterOSError(
			w,
			"Invalid provisioning URL",
		)
		return
	}

	deviceType := parts[2]
	serialReq := parts[3]
	who := []any{"device", host, "type", deviceType, "serial", serialReq}

	// fail logs why and answers the device with a script that logs it there too
	fail := func(format string, args ...any) {
		slog.Warn("provisioning failed", append(who, "reason", fmt.Sprintf(format, args...))...)
		httphelpers.WriteRouterOSError(w, format, args...)
	}

	dt, ok := s.cfg.DeviceTypes[deviceType]
	if !ok || strings.TrimSpace(dt.Community) == "" {
		fail("Unknown device type or missing community (%s)", deviceType)
		return
	}

	// 1) Read serial only
	serial, err := snmp.ReadRouterOSSerial(
		s.snmpCfg,
		host,
		dt.Community,
	)
	if err != nil {
		fail("SNMP serial read failed: %s", err.Error())
		return
	}

	// 2) Serial check
	if serial != serialReq {
		fail("Serial mismatch (expected %s)", serialReq)
		return
	}

	// 3) Full SNMP read
	snmpData, err := snmp.ReadRouterOS(
		s.snmpCfg,
		host,
		dt.Community,
	)
	if err != nil {
		fail("SNMP read failed: %s", err.Error())
		return
	}

	// 4) Ask NMS for script (and send SNMP data for inventory)
	script, err := s.nms.GetRouterOSProvisionScript(
		nms.RouterOSProvisionRequest{
			AgentID:    s.cfg.AgentID,
			DeviceType: deviceType,
			Serial:     serialReq,
			DeviceIP:   host,
			SNMP:       snmpData,
		},
	)
	if err != nil {
		fail("NMS provision failed: %s", err.Error())
		return
	}

	// 5) Return script to RouterOS
	slog.Info("provisioning script handed over", who...)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(script))
}
