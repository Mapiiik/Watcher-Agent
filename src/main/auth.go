package main

import (
	"crypto/subtle"
	"log/slog"
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

// maxBodyBytes bounds what a caller of the API may send; the debtors of a whole network fit in it many times.
const maxBodyBytes = 8 << 20

func bearerAuth(appCfg AppConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		if !strings.HasPrefix(h, "Bearer ") || !secureEqual(token, appCfg.APIToken) {
			slog.Warn("API request refused", "client", clientIP(r), "path", r.URL.Path, "reason", "invalid or missing token")
			httphelpers.WriteError(
				w,
				http.StatusUnauthorized,
				"unauthorized",
				"Invalid or missing API token.",
			)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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

// clientIP is the address of the caller, the one in the PROXY header behind the proxy.
func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		return r.RemoteAddr
	}
	return host
}

// routerOSGuard lets provisioning in only from the allowed networks and with the query token, if there is one.
// Refusals are logged by the path alone, the query holds the token.
func routerOSGuard(appCfg AppConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := clientIP(r)

		if !ipAllowed(host, appCfg.RouterOSAllowCIDRs) {
			slog.Warn("provisioning refused", "client", host, "path", r.URL.Path, "reason", "address not allowed")
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
				slog.Warn("provisioning refused", "client", host, "path", r.URL.Path, "reason", "invalid or missing query token")
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
