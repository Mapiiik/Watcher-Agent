package main

import (
    "net"
    "net/http"
    "strings"
)

func bearerAuth(appCfg AppConfig, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        h := strings.TrimSpace(r.Header.Get("Authorization"))
        if !strings.HasPrefix(h, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")) != appCfg.APIToken {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
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
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        if appCfg.RouterOSQueryToken != "" {
            if strings.TrimSpace(r.URL.Query().Get("t")) != appCfg.RouterOSQueryToken {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}
