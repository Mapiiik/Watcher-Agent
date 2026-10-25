package nms

import (
	"crypto/tls"
	"net/http"
)

// NMSClient calls the NMS API with the agent's token.
type NMSClient struct {
	cfg Config
	hc  *http.Client
}

func NewNMSClient(cfg Config) *NMSClient {
	hc := &http.Client{Timeout: cfg.Timeout}
	if cfg.SkipTLSVerify {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // only when the configuration says so
		}
		hc.Transport = t
	}

	return &NMSClient{
		cfg: cfg,
		hc:  hc,
	}
}
