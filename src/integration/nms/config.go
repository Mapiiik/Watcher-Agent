// Package nms calls the central NMS API.
package nms

import "time"

type Config struct {
	BaseURL string
	Token   string
	Timeout time.Duration
	// Only against a development NMS with a certificate of its own
	SkipTLSVerify bool
}
