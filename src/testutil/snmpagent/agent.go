// Package snmpagent is a minimal SNMP v2c agent for tests. It answers Get, GetNext and GetBulk from a fixed
// table on a local UDP port and ignores requests with another community, like a real device.
package snmpagent

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

type Agent struct {
	// Port the agent listens on, at 127.0.0.1
	Port uint16

	community string
	conn      net.PacketConn
	oids      []string
	values    map[string]gosnmp.SnmpPDU
}

// Start serves the given values until the test ends. Names are numeric OIDs with a leading dot.
func Start(t testing.TB, community string, values []gosnmp.SnmpPDU) *Agent {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("snmpagent: %v", err)
	}

	a := &Agent{
		Port:      uint16(conn.LocalAddr().(*net.UDPAddr).Port), //nolint:gosec // a UDP port fits
		community: community,
		conn:      conn,
		values:    make(map[string]gosnmp.SnmpPDU, len(values)),
	}
	for _, v := range values {
		a.values[v.Name] = v
		a.oids = append(a.oids, v.Name)
	}
	sort.Slice(a.oids, func(i, j int) bool { return compareOIDs(a.oids[i], a.oids[j]) < 0 })

	t.Cleanup(func() { _ = conn.Close() })
	go a.serve()

	return a
}

func (a *Agent) serve() {
	decoder := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.NewLogger(nil)}
	buf := make([]byte, 65535)

	for {
		n, peer, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}

		req, err := decoder.SnmpDecodePacket(buf[:n])
		if err != nil || req.Community != a.community {
			continue
		}

		resp := &gosnmp.SnmpPacket{
			Version:   gosnmp.Version2c,
			Community: a.community,
			PDUType:   gosnmp.GetResponse,
			RequestID: req.RequestID,
			Variables: a.answer(req),
		}

		out, err := resp.MarshalMsg()
		if err != nil {
			continue
		}
		_, _ = a.conn.WriteTo(out, peer)
	}
}

func (a *Agent) answer(req *gosnmp.SnmpPacket) []gosnmp.SnmpPDU {
	var out []gosnmp.SnmpPDU

	for i, v := range req.Variables {
		switch {
		case req.PDUType == gosnmp.GetRequest:
			if pdu, ok := a.values[v.Name]; ok {
				out = append(out, pdu)
			} else {
				out = append(out, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject})
			}

		case req.PDUType == gosnmp.GetNextRequest || (req.PDUType == gosnmp.GetBulkRequest && i < int(req.NonRepeaters)):
			out = append(out, a.next(v.Name, 1)...)

		case req.PDUType == gosnmp.GetBulkRequest:
			out = append(out, a.next(v.Name, int(req.MaxRepetitions))...)
		}
	}

	return out
}

// next returns up to count values following oid in the table, or EndOfMibView past its end.
func (a *Agent) next(oid string, count int) []gosnmp.SnmpPDU {
	i := sort.Search(len(a.oids), func(i int) bool { return compareOIDs(a.oids[i], oid) > 0 })

	var out []gosnmp.SnmpPDU
	for ; i < len(a.oids) && len(out) < count; i++ {
		out = append(out, a.values[a.oids[i]])
	}
	if len(out) == 0 {
		out = append(out, gosnmp.SnmpPDU{Name: oid, Type: gosnmp.EndOfMibView})
	}

	return out
}

func compareOIDs(a, b string) int {
	pa := strings.Split(strings.Trim(a, "."), ".")
	pb := strings.Split(strings.Trim(b, "."), ".")

	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x - y
		}
	}

	return len(pa) - len(pb)
}

// MinimalRouterOS is a device with the given serial, one interface and one address, the least a full read accepts.
func MinimalRouterOS(serial string) []gosnmp.SnmpPDU {
	return []gosnmp.SnmpPDU{
		Text(".1.3.6.1.4.1.14988.1.1.7.3.0", []byte(serial)),
		Int(".1.3.6.1.2.1.2.2.1.1.1", 1),
		Text(".1.3.6.1.2.1.2.2.1.2.1", []byte("ether1")),
		Int(".1.3.6.1.2.1.2.2.1.3.1", 6),
		Text(".1.3.6.1.2.1.2.2.1.6.1", []byte{0x4c, 0x5e, 0x0c, 0x01, 0x02, 0x03}),
		Int(".1.3.6.1.2.1.2.2.1.7.1", 1),
		Int(".1.3.6.1.2.1.2.2.1.8.1", 1),
		Text(".1.3.6.1.2.1.31.1.1.1.18.1", []byte("")),
		IP(".1.3.6.1.2.1.4.20.1.1.192.168.88.1", "192.168.88.1"),
		Int(".1.3.6.1.2.1.4.20.1.2.192.168.88.1", 1),
		IP(".1.3.6.1.2.1.4.20.1.3.192.168.88.1", "255.255.255.0"),
	}
}

// Text is an OCTET STRING value.
func Text(oid string, value []byte) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: value}
}

// Int is an INTEGER value.
func Int(oid string, value int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: value}
}

// Gauge is a Gauge32 value.
func Gauge(oid string, value uint) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Gauge32, Value: value}
}

// IP is an IpAddress value.
func IP(oid string, value string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.IPAddress, Value: value}
}
