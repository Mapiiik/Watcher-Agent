package httpapi

import (
	"encoding/json"
	"net/http"

	"watcher-agent/src/domain/radius"
	"watcher-agent/src/httphelpers"
)

type RadiusService struct {
	cfg radius.Config
}

func NewRadiusService(cfg radius.Config) *RadiusService {
	return &RadiusService{cfg: cfg}
}

func (s *RadiusService) HandleDisconnect(w http.ResponseWriter, r *http.Request) {
	var in radius.RadiusDisconnectInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httphelpers.WriteError(
			w,
			http.StatusBadRequest,
			"bad_request",
			"Invalid JSON request body.",
		)
		return
	}

	if in.NASIP == "" || in.Secret == "" {
		httphelpers.WriteError(
			w,
			http.StatusBadRequest,
			"bad_request",
			"Parameters 'nas_ip' and 'secret' are required.",
		)
		return
	}

	// pokud chceš, můžeš tady později:
	// in.Port = int(s.cfg.Port)
	// in.TimeoutMs = int(s.cfg.Timeout.Milliseconds())

	out, err := radius.Disconnect(in)
	if err != nil {
		httphelpers.WriteError(
			w,
			http.StatusGatewayTimeout,
			"radius_disconnect_failed",
			err.Error(),
		)
		return
	}

	httphelpers.WriteJSON(w, out)
}
