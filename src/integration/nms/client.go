package nms

import (
	"net/http"
)

// NMSClient calls the NMS API with the agent's token.
type NMSClient struct {
	cfg Config
	hc  *http.Client
}

func NewNMSClient(cfg Config) *NMSClient {
	return &NMSClient{
		cfg: cfg,
		hc:  &http.Client{Timeout: cfg.Timeout},
	}
}
