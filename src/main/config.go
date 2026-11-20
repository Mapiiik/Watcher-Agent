package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"watcher-agent/src/domain/radius"
	"watcher-agent/src/domain/routeros"
	"watcher-agent/src/domain/snmp"
	"watcher-agent/src/httpapi"
	"watcher-agent/src/infra/icmpsocket"
	"watcher-agent/src/integration/nms"
)

// AppConfig is the agent's configuration from the AGENT_* environment variables.
type AppConfig struct {
	ListenHttp       string
	ListenHttps      string
	UseProxyProtocol bool

	// Who may send a PROXY header, empty for anybody
	ProxyAllowCIDRs []string

	// Hostname for the ACME certificate, empty for a self-signed one
	Hostname string
	// Directory for the ACME certificates
	CertDir string

	// Who may call the API (status, ping, RADIUS, SNMP, RouterOS API), each with a Bearer token of its own
	APIAccess []APIAccess

	// Agent identifier, sent to the NMS and shown in the answers
	AgentID string

	// Who may call RouterOS provisioning: source addresses and an optional ?token=
	RouterOSAllowCIDRs []string
	RouterOSQueryToken string

	// Device types of the provisioning URL with the SNMP community of each
	DeviceTypes map[string]httpapi.DeviceTypeConfig

	// Kind of ICMP socket to ping over
	ICMP icmpsocket.Kind
}

// APIAccess is a caller of the API, Watcher CRM say: a name for the log and its key. Callers may share a key until
// each gets one of its own; the first with a key then names them all.
type APIAccess struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

// loadAPIAccess reads AGENT_API_ACCESS_JSON, a list of callers with their keys, and AGENT_API_TOKEN, the one key of
// the agent before the list, which becomes a caller named "default". At least one key is needed.
func loadAPIAccess() ([]APIAccess, error) {
	var list []APIAccess
	if raw := strings.TrimSpace(os.Getenv("AGENT_API_ACCESS_JSON")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return nil, fmt.Errorf("bad AGENT_API_ACCESS_JSON: %w", err)
		}
	}
	if token := strings.TrimSpace(os.Getenv("AGENT_API_TOKEN")); token != "" {
		list = append(list, APIAccess{Name: "default", Token: token})
	}

	names := make(map[string]bool, len(list))
	for i, a := range list {
		a.Name, a.Token = strings.TrimSpace(a.Name), strings.TrimSpace(a.Token)
		if a.Name == "" || a.Token == "" {
			return nil, fmt.Errorf("bad AGENT_API_ACCESS_JSON: access %d needs a name and a token", i+1)
		}
		if names[a.Name] {
			return nil, fmt.Errorf("bad AGENT_API_ACCESS_JSON: %q is there twice", a.Name)
		}
		names[a.Name] = true
		list[i] = a
	}
	if len(list) == 0 {
		return nil, errors.New("missing env: AGENT_API_ACCESS_JSON or AGENT_API_TOKEN")
	}
	return list, nil
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

// LoadAppConfig panics without a key for the API, with a broken AGENT_DEVICE_TYPES_JSON or an unknown AGENT_ICMP, so
// the agent never starts half configured.
func LoadAppConfig() AppConfig {
	deviceTypes := map[string]httpapi.DeviceTypeConfig{}
	if raw := strings.TrimSpace(os.Getenv("AGENT_DEVICE_TYPES_JSON")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &deviceTypes); err != nil {
			panic("bad AGENT_DEVICE_TYPES_JSON: " + err.Error())
		}
	}
	icmpKind, err := icmpsocket.ParseKind(strings.TrimSpace(os.Getenv("AGENT_ICMP")))
	if err != nil {
		panic("bad AGENT_ICMP: " + err.Error())
	}
	access, err := loadAPIAccess()
	if err != nil {
		panic(err.Error())
	}

	return AppConfig{
		ListenHttp:       envDefault("AGENT_LISTEN_HTTP", "0.0.0.0:80"),
		ListenHttps:      envDefault("AGENT_LISTEN_HTTPS", "0.0.0.0:443"),
		UseProxyProtocol: envDefault("AGENT_USE_PROXY_PROTOCOL", "false") == "true",

		ProxyAllowCIDRs: strings.Fields(os.Getenv("AGENT_PROXY_ALLOW_CIDRS")),

		Hostname: envDefault("AGENT_HOSTNAME", ""),
		CertDir:  envDefault("AGENT_CERT_DIR", "./certs"),

		APIAccess: access,
		AgentID:   envDefault("AGENT_ID", "agent-1"),

		RouterOSAllowCIDRs: strings.Fields(envDefault("AGENT_ROUTEROS_ALLOW_CIDRS", "0.0.0.0/0")),
		RouterOSQueryToken: strings.TrimSpace(os.Getenv("AGENT_ROUTEROS_QUERY_TOKEN")),

		DeviceTypes: deviceTypes,
		ICMP:        icmpKind,
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

// LoadRouterOSAPIConfig panics with a fingerprint or a network that is not one, so that neither check ever silently
// goes off.
func LoadRouterOSAPIConfig() routeros.Config {
	fingerprint, err := routeros.ParseFingerprint(os.Getenv("AGENT_ROUTEROS_API_CA_FINGERPRINT"))
	if err != nil {
		panic("bad AGENT_ROUTEROS_API_CA_FINGERPRINT: " + err.Error())
	}
	targets, err := routeros.ParseTargets(os.Getenv("AGENT_ROUTEROS_API_ALLOW_CIDRS"))
	if err != nil {
		panic("bad AGENT_ROUTEROS_API_ALLOW_CIDRS: " + err.Error())
	}

	return routeros.Config{
		Username: strings.TrimSpace(os.Getenv("AGENT_ROUTEROS_API_USERNAME")),
		// Not trimmed, a password may end with a space
		Password:       os.Getenv("AGENT_ROUTEROS_API_PASSWORD"),
		PlainFallback:  envDefault("AGENT_ROUTEROS_API_PLAIN_FALLBACK", "false") == "true",
		CAFingerprint:  fingerprint,
		AllowedTargets: targets,
		Timeout:        time.Duration(envIntDefault("AGENT_ROUTEROS_API_TIMEOUT_MS", 5000)) * time.Millisecond,
		TLSPort:        8729,
		PlainPort:      8728,
	}
}

func LoadNMSConfig() nms.Config {
	return nms.Config{
		BaseURL: mustEnv("AGENT_NMS_BASE_URL"),
		Token:   mustEnv("AGENT_NMS_TOKEN"),
		Timeout: 10 * time.Second,
		// Anything but an explicit "false" keeps the certificate checked
		SkipTLSVerify: envDefault("AGENT_NMS_VERIFY_TLS", "true") == "false",
	}
}
