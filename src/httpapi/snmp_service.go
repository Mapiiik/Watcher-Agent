package httpapi

import (
    "encoding/json"
    "net/http"

    "watcher-agent/src/domain/snmp"
)

type SNMPService struct {
    cfg snmp.Config
}

type SNMPReadRequest struct {
    Host      string `json:"host"`
    Community string `json:"community"`
}

func NewSNMPService(cfg snmp.Config) *SNMPService {
    return &SNMPService{cfg: cfg}
}

func (s *SNMPService) HandleRead(w http.ResponseWriter, r *http.Request) {
    var req SNMPReadRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad json", 400)
        return
    }
    if req.Host == "" || req.Community == "" {
        http.Error(w, "host and community required", 400)
        return
    }

    data, err := snmp.ReadRouterOSViaSNMP(s.cfg, req.Host, req.Community)
    if err != nil {
        http.Error(w, "snmp read failed: "+err.Error(), 500)
        return
    }

    writeJSON(w, data)
}
