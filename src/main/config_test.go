package main

import (
	"slices"
	"testing"
	"time"
)

var agentEnv = []string{
	"AGENT_LISTEN_HTTP", "AGENT_LISTEN_HTTPS", "AGENT_USE_PROXY_PROTOCOL", "AGENT_HOSTNAME", "AGENT_CERT_DIR",
	"AGENT_API_TOKEN", "AGENT_ID", "AGENT_ROUTEROS_ALLOW_CIDRS", "AGENT_ROUTEROS_QUERY_TOKEN",
	"AGENT_DEVICE_TYPES_JSON", "AGENT_SNMP_PORT", "AGENT_SNMP_TIMEOUT_MS", "AGENT_SNMP_RETRIES",
	"AGENT_RADIUS_PORT", "AGENT_RADIUS_TIMEOUT_MS", "AGENT_RADIUS_RETRIES", "AGENT_NMS_BASE_URL", "AGENT_NMS_TOKEN",
}

// cleanEnv empties every variable the agent reads; an empty value counts as not set.
func cleanEnv(t *testing.T) {
	for _, k := range agentEnv {
		t.Setenv(k, "")
	}
}

func mustPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", what)
		}
	}()
	f()
}

func TestLoadAppConfigDefaults(t *testing.T) {
	cleanEnv(t)
	t.Setenv("AGENT_API_TOKEN", " api-token ")

	cfg := LoadAppConfig()

	if cfg.ListenHttp != "0.0.0.0:80" || cfg.ListenHttps != "0.0.0.0:443" || cfg.UseProxyProtocol {
		t.Errorf("listeners = %s %s proxy %v", cfg.ListenHttp, cfg.ListenHttps, cfg.UseProxyProtocol)
	}
	if cfg.Hostname != "" || cfg.CertDir != "./certs" || cfg.AgentID != "agent-1" {
		t.Errorf("hostname %q, cert dir %q, agent %q", cfg.Hostname, cfg.CertDir, cfg.AgentID)
	}
	if cfg.APIToken != "api-token" {
		t.Errorf("API token = %q, want it trimmed", cfg.APIToken)
	}
	if !slices.Equal(cfg.RouterOSAllowCIDRs, []string{"0.0.0.0/0"}) || cfg.RouterOSQueryToken != "" {
		t.Errorf("RouterOS access = %v %q", cfg.RouterOSAllowCIDRs, cfg.RouterOSQueryToken)
	}
	if len(cfg.DeviceTypes) != 0 {
		t.Errorf("device types = %v", cfg.DeviceTypes)
	}
}

func TestLoadAppConfig(t *testing.T) {
	cleanEnv(t)
	t.Setenv("AGENT_API_TOKEN", "api-token")
	t.Setenv("AGENT_USE_PROXY_PROTOCOL", "true")
	t.Setenv("AGENT_ROUTEROS_ALLOW_CIDRS", " 10.0.0.0/8\t2a02:3c0::/29 ")
	t.Setenv("AGENT_ROUTEROS_QUERY_TOKEN", " q-token ")
	t.Setenv("AGENT_DEVICE_TYPES_JSON", `{"router":{"community":"secret"},"ap":{"community":"other"}}`)

	cfg := LoadAppConfig()

	if !cfg.UseProxyProtocol {
		t.Error("PROXY protocol off")
	}
	if !slices.Equal(cfg.RouterOSAllowCIDRs, []string{"10.0.0.0/8", "2a02:3c0::/29"}) || cfg.RouterOSQueryToken != "q-token" {
		t.Errorf("RouterOS access = %v %q", cfg.RouterOSAllowCIDRs, cfg.RouterOSQueryToken)
	}
	if cfg.DeviceTypes["router"].Community != "secret" || cfg.DeviceTypes["ap"].Community != "other" {
		t.Errorf("device types = %v", cfg.DeviceTypes)
	}
}

// Only the exact value "true" turns the PROXY protocol on.
func TestLoadAppConfigProxyProtocolNeedsTrue(t *testing.T) {
	cleanEnv(t)
	t.Setenv("AGENT_API_TOKEN", "api-token")

	for _, v := range []string{"1", "yes", "TRUE"} {
		t.Setenv("AGENT_USE_PROXY_PROTOCOL", v)
		if LoadAppConfig().UseProxyProtocol {
			t.Errorf("%q turned the PROXY protocol on", v)
		}
	}
}

func TestLoadAppConfigRefusesToStart(t *testing.T) {
	cleanEnv(t)
	mustPanic(t, "missing AGENT_API_TOKEN", func() { LoadAppConfig() })

	t.Setenv("AGENT_API_TOKEN", "api-token")
	t.Setenv("AGENT_DEVICE_TYPES_JSON", `{"router":`)
	mustPanic(t, "broken AGENT_DEVICE_TYPES_JSON", func() { LoadAppConfig() })
}

func TestLoadSNMPAndRadiusConfig(t *testing.T) {
	cleanEnv(t)

	snmpCfg, radiusCfg := LoadSNMPConfig(), LoadRadiusConfig()
	if snmpCfg.Port != 161 || snmpCfg.Timeout != 1500*time.Millisecond || snmpCfg.Retries != 1 {
		t.Errorf("SNMP defaults = %+v", snmpCfg)
	}
	if radiusCfg.Port != 1700 || radiusCfg.Timeout != 1500*time.Millisecond || radiusCfg.Retries != 1 {
		t.Errorf("RADIUS defaults = %+v", radiusCfg)
	}

	t.Setenv("AGENT_SNMP_PORT", "1161")
	t.Setenv("AGENT_SNMP_TIMEOUT_MS", "300")
	t.Setenv("AGENT_SNMP_RETRIES", "0")
	t.Setenv("AGENT_RADIUS_PORT", "3799")
	t.Setenv("AGENT_RADIUS_TIMEOUT_MS", "2000")
	t.Setenv("AGENT_RADIUS_RETRIES", "2")

	snmpCfg, radiusCfg = LoadSNMPConfig(), LoadRadiusConfig()
	if snmpCfg.Port != 1161 || snmpCfg.Timeout != 300*time.Millisecond || snmpCfg.Retries != 0 {
		t.Errorf("SNMP = %+v", snmpCfg)
	}
	if radiusCfg.Port != 3799 || radiusCfg.Timeout != 2*time.Second || radiusCfg.Retries != 2 {
		t.Errorf("RADIUS = %+v", radiusCfg)
	}

	t.Setenv("AGENT_SNMP_PORT", "161a")
	mustPanic(t, "a port that is not a number", func() { LoadSNMPConfig() })
}

func TestLoadNMSConfig(t *testing.T) {
	cleanEnv(t)
	t.Setenv("AGENT_NMS_BASE_URL", "https://nms.example.net")
	mustPanic(t, "missing AGENT_NMS_TOKEN", func() { LoadNMSConfig() })

	t.Setenv("AGENT_NMS_TOKEN", "nms-token")
	cfg := LoadNMSConfig()
	if cfg.BaseURL != "https://nms.example.net" || cfg.Token != "nms-token" || cfg.Timeout != 10*time.Second {
		t.Errorf("NMS = %+v", cfg)
	}
}
