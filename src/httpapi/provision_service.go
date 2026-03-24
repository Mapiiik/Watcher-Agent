package httpapi

import (
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

func (s *ProvisionService) HandleRouterOS(w http.ResponseWriter, r *http.Request) {
	// URL: /provision/routeros/{deviceType}/{serial}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		httphelpers.WriteRouterOSError(
			w,
			"Invalid provisioning URL",
		)
		return
	}

	deviceType := parts[2]
	serialReq := parts[3]

	dt, ok := s.cfg.DeviceTypes[deviceType]
	if !ok || strings.TrimSpace(dt.Community) == "" {
		httphelpers.WriteRouterOSError(
			w,
			"Unknown device type or missing community (%s)",
			deviceType,
		)
		return
	}

	host := remoteIP(r)

	// 1) Read serial only
	serial, err := snmp.ReadRouterOSSerial(
		s.snmpCfg,
		host,
		dt.Community,
	)
	if err != nil {
		httphelpers.WriteRouterOSError(
			w,
			"SNMP serial read failed: %s",
			err.Error(),
		)
		return
	}

	// 2) Serial check
	if serial != serialReq {
		httphelpers.WriteRouterOSError(
			w,
			"Serial mismatch (got %s, expected %s)",
			serial,
			serialReq,
		)
		return
	}

	// 3) Full SNMP read
	snmpData, err := snmp.ReadRouterOS(
		s.snmpCfg,
		host,
		dt.Community,
	)
	if err != nil {
		httphelpers.WriteRouterOSError(
			w,
			"SNMP read failed: %s",
			err.Error(),
		)
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
		httphelpers.WriteRouterOSError(
			w,
			"NMS provision failed: %s",
			err.Error(),
		)
		return
	}

	// 5) Return script to RouterOS
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(script))
}
