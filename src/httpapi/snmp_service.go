package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/httphelpers"
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

func (s *SNMPService) HandleRouterOSRead(w http.ResponseWriter, r *http.Request) {
	var req SNMPReadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httphelpers.WriteError(
			w,
			http.StatusBadRequest,
			"bad_request",
			"Invalid JSON request body.",
		)
		return
	}

	if req.Host == "" || req.Community == "" {
		httphelpers.WriteError(
			w,
			http.StatusBadRequest,
			"bad_request",
			"Parameters 'host' and SNMP 'community' are required.",
		)
		return
	}

	data, err := snmp.ReadRouterOS(s.cfg, req.Host, req.Community)
	if err != nil {
		httphelpers.WriteError(
			w,
			http.StatusBadGateway,
			"snmp_read_failed",
			fmt.Sprintf("Failed to read data from the SNMP device: %s", err),
		)
		return
	}

	httphelpers.WriteJSON(w, data)
}
