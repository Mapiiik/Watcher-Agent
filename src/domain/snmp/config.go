// Package snmp reads RouterOS devices over SNMP v2c.
package snmp

import (
	"time"
)

type Config struct {
	Port    uint16
	Timeout time.Duration
	Retries int
}
