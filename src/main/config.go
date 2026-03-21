package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"watcher-agent/src/domain/radius"
	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/httpapi"
	"watcher-agent/src/integration/nms"
)

type AppConfig struct {
	ListenHttp  string
	ListenHttps string

	// for ACME TLS, if empty - self-signed cert will be used
	Hostname    string
	// directory for ACME cert storage (default: "./certs")
	CertDir     string
	
	// Auth for API calls (ping/radius/snmp) from Watcher/NMS/CRM
	APIToken string

	// Agent identificator
	AgentID string

	// RouterOS provisioning access control (MVP)
	RouterOSAllowCIDRs []string
	RouterOSQueryToken string // optional

	// Device types (agent-side lookup for SNMP community)
	DeviceTypes map[string]httpapi.DeviceTypeConfig
}

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		panic("missing env: " + key)
	}
	return v
}

func envDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func envIntDefault(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		panic("bad int env " + key + ": " + err.Error())
	}
	return i
}

func LoadAppConfig() AppConfig {
	deviceTypes := map[string]httpapi.DeviceTypeConfig{}
	if raw := strings.TrimSpace(os.Getenv("AGENT_DEVICE_TYPES_JSON")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &deviceTypes); err != nil {
			panic("bad AGENT_DEVICE_TYPES_JSON: " + err.Error())
		}
	}

	return AppConfig{
		ListenHttp:  envDefault("AGENT_LISTEN_HTTP", "0.0.0.0:80"),
		ListenHttps: envDefault("AGENT_LISTEN_HTTPS", "0.0.0.0:443"),

		Hostname:    envDefault("AGENT_HOSTNAME", ""),
		CertDir:     envDefault("AGENT_CERT_DIR", "./certs"),

		APIToken: mustEnv("AGENT_API_TOKEN"),
		AgentID:  envDefault("AGENT_ID", "agent-1"),

		RouterOSAllowCIDRs: strings.Fields(envDefault("AGENT_ROUTEROS_ALLOW_CIDRS", "0.0.0.0/0")),
		RouterOSQueryToken: strings.TrimSpace(os.Getenv("AGENT_ROUTEROS_QUERY_TOKEN")),

		DeviceTypes: deviceTypes,
	}
}

func LoadSNMPConfig() snmp.Config {
	return snmp.Config{
		Port:    uint16(envIntDefault("AGENT_SNMP_PORT", 161)),
		Timeout: time.Duration(envIntDefault("AGENT_SNMP_TIMEOUT_MS", 1500)) * time.Millisecond,
		Retries: envIntDefault("AGENT_SNMP_RETRIES", 1),
	}
}

func LoadRadiusConfig() radius.Config {
	return radius.Config{
		Port:    uint16(envIntDefault("AGENT_RADIUS_PORT", 1700)),
		Timeout: time.Duration(envIntDefault("AGENT_RADIUS_TIMEOUT_MS", 1500)) * time.Millisecond,
		Retries: envIntDefault("AGENT_RADIUS_RETRIES", 1),
	}
}

func LoadNMSConfig() nms.Config {
	return nms.Config{
		BaseURL: mustEnv("AGENT_NMS_BASE_URL"),
		Token:   mustEnv("AGENT_NMS_TOKEN"),
		Timeout: 10 * time.Second,
	}
}
