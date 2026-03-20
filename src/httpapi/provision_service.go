package httpapi

import (
    "fmt"
    "net/http"
    "strings"

    "watcher-agent/src/domain/snmp"
    "watcher-agent/src/integration/nms"
)

type ProvisionService struct {
    cfg     ProvisionConfig
    snmpCfg snmp.Config
    nms     *nms.NMSClient
}

func NewProvisionService(
    cfg     ProvisionConfig,
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
    // URL: /routeros/provision/{deviceType}/{serial}
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) != 4 {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprint(
            w,
            ":log error \"Watcher Agent: Invalid provisioning URL\"\n",
        )
        return
    }

    deviceType := parts[2]
    serialReq := parts[3]

    dt, ok := s.cfg.DeviceTypes[deviceType]
    if !ok || strings.TrimSpace(dt.Community) == "" {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(
            w,
            ":log error \"Watcher Agent: Unknown device type or missing community (%s)\"\n",
            escapeROS(deviceType),
        )
        return
    }

    host := remoteIP(r)

    // 1) SNMP read
    snmpData, err := snmp.ReadRouterOSViaSNMP(
        s.snmpCfg,
        host,
        dt.Community,
    )
    if err != nil {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(
            w,
            ":log error \"Watcher Agent: SNMP read failed: %s\"\n",
            escapeROS(err.Error()),
        )
        return
    }

    // 2) Serial check
    if snmpData.Device.Serial != serialReq {
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(
            w,
            ":log error \"Watcher Agent: Serial mismatch (got %s, expected %s)\"\n",
            escapeROS(snmpData.Device.Serial),
            escapeROS(serialReq),
        )
        return
    }

    // 3) Ask NMS for script
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
        w.Header().Set("Content-Type", "text/plain")
        fmt.Fprintf(
            w,
            ":log error \"Watcher Agent: NMS provision failed: %s\"\n",
            escapeROS(err.Error()),
        )
        return
    }

    // 4) Return script to RouterOS
    w.Header().Set("Content-Type", "text/plain")
    _, _ = w.Write([]byte(script))
}
