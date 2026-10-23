package main

import (
	"net"
	"net/http"
	"strings"

	"watcher-agent/src/domain/radius"
	"watcher-agent/src/domain/routeros"
	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/httpapi"
	"watcher-agent/src/integration/nms"
)

// newHandler wires the endpoints: the API behind the Bearer token, RouterOS provisioning behind the address
// list and the optional query token, all of it behind the drain middleware.
func newHandler(
	appCfg AppConfig,
	radiusCfg radius.Config,
	snmpCfg snmp.Config,
	nmsCfg nms.Config,
	routerOSCfg routeros.Config,
) http.Handler {
	provCfg := httpapi.ProvisionConfig{
		AgentID:     appCfg.AgentID,
		DeviceTypes: appCfg.DeviceTypes,
	}

	nmsClient := nms.NewNMSClient(nmsCfg)

	rootSvc := httpapi.NewRootService(appCfg.AgentID)
	statusSvc := httpapi.NewStatusService(
		appCfg.AgentID,
		appCfg.DeviceTypes,
	)
	pingSvc := httpapi.NewPingService()
	radiusSvc := httpapi.NewRadiusService(radiusCfg)
	snmpSvc := httpapi.NewSNMPService(snmpCfg)
	routerOSSvc := httpapi.NewRouterOSService(routerOSCfg)
	provisionSvc := httpapi.NewProvisionService(
		provCfg,
		snmpCfg,
		nmsClient,
	)

	mux := http.NewServeMux()

	// Health check, and 404 for every unknown path
	mux.HandleFunc("/", rootSvc.HandleRoot)

	// API endpoints (guarded by Bearer token)
	mux.Handle(
		"/api/status",
		bearerAuth(appCfg, http.HandlerFunc(statusSvc.HandleStatus)),
	)
	mux.Handle(
		"/api/ping",
		bearerAuth(appCfg, http.HandlerFunc(pingSvc.HandlePing)),
	)

	mux.Handle(
		"/api/radius/disconnect",
		bearerAuth(appCfg, http.HandlerFunc(radiusSvc.HandleDisconnect)),
	)

	mux.Handle(
		"/api/snmp/read/routeros",
		bearerAuth(appCfg, http.HandlerFunc(snmpSvc.HandleRouterOSRead)),
	)

	mux.Handle(
		"/api/routeros/address-list/sync",
		bearerAuth(appCfg, http.HandlerFunc(routerOSSvc.HandleAddressListSync)),
	)
	mux.Handle(
		"/api/routeros/address-list/add",
		bearerAuth(appCfg, http.HandlerFunc(routerOSSvc.HandleAddressListAdd)),
	)
	mux.Handle(
		"/api/routeros/address-list/remove",
		bearerAuth(appCfg, http.HandlerFunc(routerOSSvc.HandleAddressListRemove)),
	)
	mux.Handle(
		"/api/routeros/access-list/remove",
		bearerAuth(appCfg, http.HandlerFunc(routerOSSvc.HandleAccessListRemove)),
	)

	// RouterOS provisioning (guarded by allowlist + optional query token)
	mux.Handle(
		"/provision/routeros/",
		routerOSGuard(appCfg, http.HandlerFunc(provisionSvc.HandleRouterOS)),
	)

	// Wrap mux with drain middleware to reject new requests during shutdown
	return drainMiddleware(mux)
}

// httpsRedirect sends plain HTTP requests to the same host and path on the HTTPS port.
func httpsRedirect(listenHTTPS string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Remove the port from the Host header, and the brackets of an IPv6 address sent without one
		host := strings.TrimSuffix(strings.TrimPrefix(r.Host, "["), "]")
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}

		// Extract HTTPS port from config
		_, tlsPort, err := net.SplitHostPort(listenHTTPS)
		if err != nil {
			http.Error(w, "invalid HTTPS address", http.StatusInternalServerError)
			return
		}

		u := *r.URL
		u.Scheme = "https"
		u.Host = net.JoinHostPort(host, tlsPort)

		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	})
}
