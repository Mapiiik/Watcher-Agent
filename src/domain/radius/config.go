// Package radius disconnects sessions on a NAS with RADIUS Disconnect-Request (RFC 5176).
package radius

import (
	"time"
)

type Config struct {
	Port    uint16
	Timeout time.Duration
	Retries int
}
