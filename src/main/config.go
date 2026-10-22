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

// AppConfig is the agent's configuration from the AGENT_* environment variables.
type AppConfig struct {
	ListenHttp       string
	ListenHttps      string
	UseProxyProtocol bool

	// Hostname for the ACME certificate, empty for a self-signed one
	Hostname string
	// Directory for the ACME certificates
	CertDir string

	// Bearer token for the API calls (status, ping, RADIUS, SNMP) from Watcher, NMS and CRM
	APIToken string

	// Agent identifier, sent to the NMS and shown in the answers
	AgentID string

	// Who may call RouterOS provisioning: source addresses and an optional ?token=
	RouterOSAllowCIDRs []string
	RouterOSQueryToken string

	// Device types of the provisioning URL with the SNMP community of each
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

// LoadAppConfig panics without AGENT_API_TOKEN or with a broken AGENT_DEVICE_TYPES_JSON, so the agent never
// starts half configured.
func LoadAppConfig() AppConfig {
	deviceTypes := map[string]httpapi.DeviceTypeConfig{}
	if raw := strings.TrimSpace(os.Getenv("AGENT_DEVICE_TYPES_JSON")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &deviceTypes); err != nil {
			panic("bad AGENT_DEVICE_TYPES_JSON: " + err.Error())
		}
	}

	return AppConfig{
		ListenHttp:       envDefault("AGENT_LISTEN_HTTP", "0.0.0.0:80"),
		ListenHttps:      envDefault("AGENT_LISTEN_HTTPS", "0.0.0.0:443"),
		UseProxyProtocol: envDefault("AGENT_USE_PROXY_PROTOCOL", "false") == "true",

		Hostname: envDefault("AGENT_HOSTNAME", ""),
		CertDir:  envDefault("AGENT_CERT_DIR", "./certs"),

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
