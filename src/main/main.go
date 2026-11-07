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

	if err := run(appCfg, srvHTTP, srvHTTPS, sigChan); err != nil {
		log.Fatalf("HTTPS server error: %v", err)
	}
	log.Println("Watcher Agent stopped gracefully")
}

// run serves until a signal comes, or until HTTPS stops by itself. Plain HTTP only redirects to it, so the agent has
// nothing left to do then, and ending with the error lets Docker start it again.
func run(cfg AppConfig, srvHTTP, srvHTTPS *http.Server, signals <-chan os.Signal) error {
	// Start HTTP redirect server
	go func() {
		log.Printf("Watcher Agent listening HTTP on %s", cfg.ListenHttp)
		if err := srvHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server
	httpsStopped := make(chan error, 1)
	go func() { httpsStopped <- serveHTTPS(cfg, srvHTTPS) }()

	select {
	case <-signals:
		log.Println("Shutdown signal received")
		shutdown(shutdownTimeout, srvHTTP, srvHTTPS)
		return <-httpsStopped

	case err := <-httpsStopped:
		shutdown(shutdownTimeout, srvHTTP, srvHTTPS)
		return err
	}
}

// serveHTTPS serves until the server is shut down, which is no error, or fails.
func serveHTTPS(cfg AppConfig, srv *http.Server) error {
	var err error

	if cfg.UseProxyProtocol {
		// Start HTTPS with PROXY protocol support
		ln, listenErr := net.Listen("tcp", srv.Addr)
		if listenErr != nil {
			return listenErr
		}

		log.Printf("Watcher Agent listening HTTPS on %s (PROXY protocol support enabled)", srv.Addr)
		err = srv.ServeTLS(newProxyListener(ln, cfg.ProxyAllowCIDRs), "", "")
	} else {
		// Start HTTPS server without PROXY protocol support
		log.Printf("Watcher Agent listening HTTPS on %s (PROXY protocol support disabled)", srv.Addr)
		err = srv.ListenAndServeTLS("", "")
	}

	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
