package httpapi

import (
    "encoding/json"
    "net"
    "net/http"
    "strings"
)

func writeJSON(w http.ResponseWriter, v any) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(v)
}

func remoteIP(r *http.Request) string {
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    if host == "" {
        return r.RemoteAddr
    }
    return host
}

func escapeROS(s string) string {
    s = strings.ReplaceAll(s, `"`, `'`)
    s = strings.ReplaceAll(s, "\n", " ")
    return s
}
