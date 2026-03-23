package main

import (
	"log"
	"net"
	"net/http"

	"watcher-agent/src/httpapi"
	"watcher-agent/src/integration/nms"

	"github.com/pires/go-proxyproto"
)

func main() {
	// Load configuration
	appCfg := LoadAppConfig()
	radiusCfg := LoadRadiusConfig()
	snmpCfg := LoadSNMPConfig()
	nmsCfg := LoadNMSConfig()
	provCfg := httpapi.ProvisionConfig{
		AgentID:     appCfg.AgentID,
		DeviceTypes: appCfg.DeviceTypes,
	}

	// Initialise NMS API client
	nmsClient := nms.NewNMSClient(nmsCfg)

	// Create HTTP handlers
	statusSvc := httpapi.NewStatusService(
		appCfg.AgentID,
		appCfg.DeviceTypes,
	)
	pingSvc := httpapi.NewPingService()
	radiusSvc := httpapi.NewRadiusService(radiusCfg)
	snmpSvc := httpapi.NewSNMPService(snmpCfg)
	provisionSvc := httpapi.NewProvisionService(
		provCfg,
		snmpCfg,
		nmsClient,
	)

	// HTTP request multiplexer
	mux := http.NewServeMux()

	// Root endpoint for health checks
	mux.HandleFunc("/", handleRoot)

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

	// RouterOS provisioning (guarded by allowlist + optional query token)
	mux.Handle(
		"/provision/routeros/",
		routerOSGuard(appCfg, http.HandlerFunc(provisionSvc.HandleRouterOS)),
	)

	// HTTP server (redirect)
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		// Remove port from Host header if present
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}

		// Extract HTTPS port from config
		_, tlsPort, err := net.SplitHostPort(appCfg.ListenHttps)
		if err != nil {
			http.Error(w, "invalid HTTPS address", http.StatusInternalServerError)
			return
		}

		u := *r.URL
		u.Scheme = "https"
		u.Host = net.JoinHostPort(host, tlsPort)

		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	})
	srvHTTP := &http.Server{
		Addr:    appCfg.ListenHttp,
		Handler: redirect,
	}

	// Start HTTP in background
	go func() {
		log.Printf("Watcher Agent listening HTTP on %s", appCfg.ListenHttp)
		if err := srvHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// HTTPS server (ACME or self-signed)
	srvHTTPS, err := buildHTTPServer(appCfg, mux)
	if err != nil {
		log.Fatal(err)
	}

	if appCfg.UseProxyProtocol {
		// Start HTTPS (blocking) with PROXY protocol support
		ln, err := net.Listen("tcp", srvHTTPS.Addr)
		if err != nil {
			log.Fatal(err)
		}

		proxyListener := &proxyproto.Listener{
			Listener: ln,
		}
		defer proxyListener.Close()

		log.Printf("Watcher Agent listening HTTPS on %s (PROXY protocol enabled)", srvHTTPS.Addr)
		log.Fatal(srvHTTPS.ServeTLS(proxyListener, "", ""))
	} else {
		// Start HTTPS (blocking)
		log.Printf("Watcher Agent listening HTTPS on %s", srvHTTPS.Addr)
		log.Fatal(srvHTTPS.ListenAndServeTLS("", ""))
	}
}
