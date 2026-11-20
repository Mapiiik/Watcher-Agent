// Package routeros changes RouterOS devices over their binary API: api-ssl first, the plain api only where the
// router cannot do TLS and the configuration allows it.
package routeros

import (
	"encoding/hex"
	"fmt"
	"net"
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

	// Networks the agent may log in to, nil for any address. Without a CA to verify against, whoever answers on an
	// address gets the login, encrypted or not, so this keeps it inside the own network.
	AllowedTargets []*net.IPNet

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

// ParseTargets reads space-separated networks, a bare address being a network of its own. An empty string is no
// limit at all, nil.
func ParseTargets(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, field := range strings.Fields(s) {
		if strings.Contains(field, "/") {
			_, n, err := net.ParseCIDR(field)
			if err != nil {
				return nil, fmt.Errorf("not a network: %q", field)
			}
			nets = append(nets, n)
			continue
		}

		ip := net.ParseIP(field)
		if ip == nil {
			return nil, fmt.Errorf("not an address: %q", field)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(len(ip)*8, len(ip)*8)})
	}

	return nets, nil
}

// allows tells whether the address is inside the networks, any address when there are none.
func (c Config) allows(ip net.IP) bool {
	if c.AllowedTargets == nil {
		return true
	}
	for _, n := range c.AllowedTargets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
