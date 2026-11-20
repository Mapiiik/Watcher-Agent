package httpapi

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"watcher-agent/src/httphelpers"
)

type StatusService struct {
	agentID string
	// version is told to callers with a key only, not to anybody asking at the root
	version string
	// Only the names, the communities are nobody's business here
	deviceTypes []string
	startTime   time.Time
}

func NewStatusService(
	agentID string,
	version string,
	deviceTypes map[string]DeviceTypeConfig,
) *StatusService {
	names := slices.AppendSeq(make([]string, 0, len(deviceTypes)), maps.Keys(deviceTypes))
	slices.Sort(names)

	return &StatusService{
		agentID:     agentID,
		version:     version,
		deviceTypes: names,
		startTime:   time.Now(),
	}
}

func (s *StatusService) HandleStatus(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime)

	out := map[string]any{
		"service":        "watcher-agent",
		"status":         "ok",
		"agent_id":       s.agentID,
		"version":        s.version,
		"started_at":     s.startTime.UTC().Format(time.RFC3339),
		"uptime":         formatUptime(uptime),
		"uptime_seconds": int64(uptime.Seconds()),
		"capabilities": map[string]any{
			"device_types": s.deviceTypes,
		},
	}

	httphelpers.WriteJSON(w, out)
}

func formatUptime(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
