package snmp

import (
    "encoding/hex"
    "fmt"
    "net"
    "strings"
)

func snmpText(v any) string {
    if b, ok := v.([]byte); ok {
        return string(b)
    }
    return fmt.Sprintf("%v", v)
}

func macToString(v any) string {
    // gosnmp often returns []byte for OctetString
    b, ok := v.([]byte)
    if !ok || len(b) == 0 {
        return ""
    }
    // format aa:bb:cc:dd:ee:ff
    h := hex.EncodeToString(b)
    if len(h) < 12 {
        return ""
    }
    parts := []string{}
    for i := 0; i+2 <= len(h); i += 2 {
        parts = append(parts, h[i:i+2])
    }
    return strings.Join(parts, ":")
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
