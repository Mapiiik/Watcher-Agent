package httpapi

import (
	"net/http"

	"watcher-agent/src/httphelpers"
)

// Repository is where the source of Watcher Agent is, offered at the root as the AGPL asks of a program used over a
// network.
const Repository = "https://github.com/Mapiiik/Watcher-Agent"

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
		"source":   Repository,
	}

	httphelpers.WriteJSON(w, out)
}
