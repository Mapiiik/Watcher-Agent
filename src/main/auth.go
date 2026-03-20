package main

import (
    "net"
    "net/http"
    "strings"

    "watcher-agent/src/httphelpers"
)

func bearerAuth(appCfg AppConfig, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        h := strings.TrimSpace(r.Header.Get("Authorization"))
        if !strings.HasPrefix(h, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")) != appCfg.APIToken {
            httphelpers.WriteError(
                w,
                http.StatusUnauthorized,
                "unauthorized",
                "Invalid or missing API token.",
            )
            return
        }
        next.ServeHTTP(w, r)
    })
}

func ipAllowed(remoteIP string, cidrs []string) bool {
    ip := net.ParseIP(remoteIP)
    if ip == nil {
        return false
    }
    for _, c := range cidrs {
        _, n, err := net.ParseCIDR(c)
        if err == nil && n.Contains(ip) {
            return true
        }
    }
    return false
}

func routerOSGuard(appCfg AppConfig, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        host, _, _ := net.SplitHostPort(r.RemoteAddr)
        if host == "" {
            host = r.RemoteAddr
        }

        if !ipAllowed(host, appCfg.RouterOSAllowCIDRs) {
            httphelpers.WriteError(
                w,
                http.StatusForbidden,
                "forbidden",
                "Access from this IP address is not allowed.",
            )
            return
        }

        if appCfg.RouterOSQueryToken != "" {
            if strings.TrimSpace(r.URL.Query().Get("t")) != appCfg.RouterOSQueryToken {
                httphelpers.WriteError(
                    w,
                    http.StatusForbidden,
                    "forbidden",
                    "Invalid or missing RouterOS query token.",
                )
                return
            }
        }

        next.ServeHTTP(w, r)
    })
}
