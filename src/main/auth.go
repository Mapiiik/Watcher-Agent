package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"watcher-agent/src/httphelpers"
)

// secureEqual compares two strings in constant time to avoid leaking how many
// leading characters matched via response timing. Length is not secret here.
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func bearerAuth(appCfg AppConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		if !strings.HasPrefix(h, "Bearer ") || !secureEqual(token, appCfg.APIToken) {
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
			if !secureEqual(strings.TrimSpace(r.URL.Query().Get("token")), appCfg.RouterOSQueryToken) {
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
