package httpapi

import (
	"net/http"

	"watcher-agent/src/httphelpers"
)

type RootService struct {
	agentID string
}

func NewRootService(
	agentID string,
) *RootService {
	return &RootService{
		agentID: agentID,
	}
}

func (s *RootService) HandleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	out := map[string]any{
		"service":  "watcher-agent",
		"status":   "ok",
		"agent_id": s.agentID,
	}

	httphelpers.WriteJSON(w, out)
}
