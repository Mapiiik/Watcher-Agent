package httpapi

import (
    "encoding/json"
    "net/http"

    "watcher-agent/src/domain/radius"
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
        http.Error(w, "bad json", 400)
        return
    }

    if in.NASIP == "" || in.Secret == "" {
        http.Error(w, "nas_ip and secret required", 400)
        return
    }

    // pokud chceš, můžeš tady později:
    // in.Port = int(s.cfg.Port)
    // in.TimeoutMs = int(s.cfg.Timeout.Milliseconds())

    out, err := radius.Disconnect(in)
    if err != nil {
        http.Error(w, "radius disconnect failed: "+err.Error(), 500)
        return
    }

    writeJSON(w, out)
}
