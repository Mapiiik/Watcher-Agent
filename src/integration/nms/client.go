package nms

import (
    "net/http"
)

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
