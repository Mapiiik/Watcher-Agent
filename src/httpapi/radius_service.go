package httpapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"watcher-agent/src/domain/radius"
	"watcher-agent/src/httphelpers"
)

// maxRadiusTimeoutMs is what one attempt may wait for the NAS; a NAS answers within a second or not at all.
const maxRadiusTimeoutMs = 10_000

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

	if in.TimeoutMs > maxRadiusTimeoutMs {
		httphelpers.WriteError(
			w,
			http.StatusBadRequest,
			"bad_request",
			fmt.Sprintf("'timeout_ms' may be %d at most.", maxRadiusTimeoutMs),
		)
		return
	}

	// The secret never goes into the log
	who := []any{
		"client", remoteIP(r), "caller", httphelpers.Caller(r), "nas", in.NASIP, "username", in.UserName,
		"session", in.AcctSessionID, "framed_ip", in.FramedIP,
	}

	out, err := radius.Disconnect(s.cfg, in)
	if err != nil {
		slog.Warn("RADIUS disconnect failed", append(who, "error", err)...)
		httphelpers.WriteError(
			w,
			http.StatusInternalServerError,
			"internal_error",
			err.Error(),
		)
		return
	}

	slog.Info("RADIUS disconnect", append(who, "result", out.Result)...)
	httphelpers.WriteJSON(w, out)
}
