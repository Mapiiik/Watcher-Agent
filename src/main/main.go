package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"watcher-agent/src/httpapi"
	"watcher-agent/src/integration/nms"

	"github.com/pires/go-proxyproto"
)

func main() {
	// Channel to listen for OS signals (e.g. SIGINT, SIGTERM)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

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
	rootSvc := httpapi.NewRootService(appCfg.AgentID)
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

	// RouterOS provisioning (guarded by allowlist + optional query token)
	mux.Handle(
		"/provision/routeros/",
		routerOSGuard(appCfg, http.HandlerFunc(provisionSvc.HandleRouterOS)),
	)

	// Wrap mux with drain middleware to reject new requests during shutdown
	wrappedMux := drainMiddleware(mux)

	// Redirect to HTTPS for HTTP server
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

	// HTTP server
	srvHTTP := &http.Server{
		Addr:    appCfg.ListenHttp,
		Handler: redirect,
	}

	// HTTPS server (ACME or self-signed)
	srvHTTPS, err := buildHTTPServer(appCfg, wrappedMux)
	if err != nil {
		log.Fatal(err)
	}

	// Channel to signal HTTPS serve loop exit
	httpsStopped := make(chan struct{}, 1)

	// Start HTTP redirect server
	go func() {
		log.Printf("Watcher Agent listening HTTP on %s", appCfg.ListenHttp)
		if err := srvHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server
	go func() {
		defer func() { httpsStopped <- struct{}{} }()

		if appCfg.UseProxyProtocol {
			// Start HTTPS with PROXY protocol support
			ln, err := net.Listen("tcp", srvHTTPS.Addr)
			if err != nil {
				log.Fatal(err)
			}
			proxyListener := &proxyproto.Listener{Listener: ln}

			log.Printf("Watcher Agent listening HTTPS on %s (PROXY protocol support enabled)", srvHTTPS.Addr)
			if err := srvHTTPS.ServeTLS(proxyListener, "", ""); err != nil &&
				!errors.Is(err, http.ErrServerClosed) &&
				!errors.Is(err, net.ErrClosed) {
				log.Printf("HTTPS server error: %v", err)
			}
		} else {
			// Start HTTPS server without PROXY protocol support
			log.Printf("Watcher Agent listening HTTPS on %s (PROXY protocol support disabled)", srvHTTPS.Addr)
			if err := srvHTTPS.ListenAndServeTLS("", ""); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				log.Printf("HTTPS server error: %v", err)
			}
		}
	}()

	// Graceful shutdown
	<-sigChan
	log.Println("Shutdown signal received")

	// Set draining flag to reject new requests
	draining.Store(true)

	// Wait for active requests to finish
	activeRequests.Wait()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srvHTTP.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
	if err := srvHTTPS.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTPS shutdown error: %v", err)
	}

	<-httpsStopped
	log.Println("Watcher Agent stopped gracefully")
}
