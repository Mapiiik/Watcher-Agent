package main

import (
	"log"
	"net/http"

	"watcher-agent/src/httpapi"
	"watcher-agent/src/integration/nms"
)

func main() {
	appCfg := LoadAppConfig()

	radiusCfg := LoadRadiusConfig()
	snmpCfg := LoadSNMPConfig()
	nmsCfg := LoadNMSConfig()
	provCfg := httpapi.ProvisionConfig{
		AgentID:     appCfg.AgentID,
		DeviceTypes: appCfg.DeviceTypes,
	}

	nmsClient := nms.NewNMSClient(nmsCfg)

	pingSvc := httpapi.NewPingService()
	radiusSvc := httpapi.NewRadiusService(radiusCfg)
	snmpSvc := httpapi.NewSNMPService(snmpCfg)
	provisionSvc := httpapi.NewProvisionService(
		provCfg,
		snmpCfg,
		nmsClient,
	)

	mux := http.NewServeMux()

	// RouterOS provisioning (guarded by allowlist + optional query token)
	mux.Handle(
		"/routeros/provision/",
		routerOSGuard(appCfg, http.HandlerFunc(provisionSvc.HandleRouterOS)),
	)

	// API endpoints (guarded by Bearer token)
	mux.Handle(
		"/api/ping",
		bearerAuth(appCfg, http.HandlerFunc(pingSvc.HandlePing)),
	)

	mux.Handle(
		"/api/radius/disconnect",
		bearerAuth(appCfg, http.HandlerFunc(radiusSvc.HandleDisconnect)),
	)

	mux.Handle(
		"/api/snmp/read",
		bearerAuth(appCfg, http.HandlerFunc(snmpSvc.HandleRead)),
	)

	srv := &http.Server{
		Addr:    appCfg.ListenAddr,
		Handler: mux,
	}

	log.Printf("Watcher-Agent listening on %s", appCfg.ListenAddr)
	log.Fatal(srv.ListenAndServe())
}
