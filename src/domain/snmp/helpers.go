package snmp

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

func snmpText(v any) *string {
	if v == nil {
		return nil
	}
	if b, ok := v.([]byte); ok {
		if len(b) == 0 {
			return nil
		}
		s := string(b)
		return &s
	}
	s := fmt.Sprintf("%v", v)
	if s == "" || s == "<nil>" {
		return nil
	}
	return &s
}

func snmpInt(v any) *int {
	var i int

	switch t := v.(type) {
	case int:
		i = t
	case int64:
		i = int(t)
	case uint:
		//for Counter32, Gauge32, etc.
		i = int(t)
	case uint32:
		i = int(t)
	case uint64:
		i = int(t)
	default:
		return nil
	}
	return &i
}

func macToString(v any) *string {
	b, ok := v.([]byte)
	if !ok || len(b) == 0 {
		return nil
	}

	h := hex.EncodeToString(b)
	if len(h) < 12 {
		return nil
	}

	parts := []string{}
	for i := 0; i+2 <= len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}

	s := strings.Join(parts, ":")
	return &s
}

func maskToCIDR(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return -1
	}
	ip = ip.To4()
	if ip == nil {
		return -1
	}
	ones, bits := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3]).Size()
	if bits != 32 {
		return -1
	}
	return ones
}
