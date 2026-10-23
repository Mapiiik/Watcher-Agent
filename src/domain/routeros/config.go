// Package routeros changes RouterOS devices over their binary API: api-ssl first, the plain api only where the
// router cannot do TLS and the configuration allows it.
package routeros

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Config struct {
	// Account on the devices, empty when the agent is not to talk to their API at all
	Username string
	Password string

	// Allow the plain api when api-ssl is refused or the router has no certificate for it
	PlainFallback bool

	// SHA-256 of the CA the router's certificate must be signed by, nil to encrypt without verifying
	CAFingerprint []byte

	// For the connection and for each command
	Timeout time.Duration

	// Ports of api-ssl and api, fields so that tests can move them
	TLSPort   int
	PlainPort int
}

// Configured tells whether there is an account to log in with.
func (c Config) Configured() bool {
	return c.Username != ""
}

// ParseFingerprint reads a SHA-256 fingerprint the way RouterOS and OpenSSL print it: hex, in either case, with or
// without colons. An empty string is no fingerprint.
func ParseFingerprint(s string) ([]byte, error) {
	s = strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s))
	if s == "" {
		return nil, nil
	}

	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("not a SHA-256 fingerprint: %q", s)
	}

	return b, nil
}
