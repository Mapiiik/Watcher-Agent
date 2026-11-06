// Watcher Agent is a small HTTPS agent next to the network: it pings, disconnects RADIUS sessions, reads RouterOS
// over SNMP and changes its address and access lists over the RouterOS API for Watcher, NMS and CRM, and provisions
// RouterOS devices with scripts from the NMS.
package main

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Channel to listen for OS signals (e.g. SIGINT, SIGTERM)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	appCfg := LoadAppConfig()
	radiusCfg := LoadRadiusConfig()
	snmpCfg := LoadSNMPConfig()
	nmsCfg := LoadNMSConfig()
	routerOSCfg := LoadRouterOSAPIConfig()

	// Plain HTTP only redirects to HTTPS
	srvHTTP := newServer(appCfg.ListenHttp, httpsRedirect(appCfg.ListenHttps))

	// HTTPS server (ACME or self-signed)
	srvHTTPS, err := buildHTTPServer(appCfg, newHandler(appCfg, radiusCfg, snmpCfg, nmsCfg, routerOSCfg))
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
			proxyListener := newProxyListener(ln, appCfg.ProxyAllowCIDRs)

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

	shutdown(shutdownTimeout, srvHTTP, srvHTTPS)

	<-httpsStopped
	log.Println("Watcher Agent stopped gracefully")
}
