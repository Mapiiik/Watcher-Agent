package snmp

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// errSNMPEmpty is returned by snmpGetText when an OID is absent or its value
// is empty after all retries. It is distinct from transport/protocol errors so
// callers can decide whether to treat the absence as nil or as a failure.
var errSNMPEmpty = errors.New("snmp value empty")

const snmpAttempts = 3

type SNMPDevice struct {
	Serial            string  `json:"serial_number"`
	IP                string  `json:"ip_address"`
	Name              *string `json:"name"`
	SystemDescription *string `json:"system_description"`
	BoardName         *string `json:"board_name"`
	SoftwareVersion   *string `json:"software_version"`
	FirmwareVersion   *string `json:"firmware_version"`
}

// Pointer fields are used to preserve null semantics when SNMP values are missing
type SNMPInterface struct {
	InterfaceIndex int     `json:"interface_index"`
	Name           *string `json:"name"`
	Comment        *string `json:"comment"`
	AdminStatus    *int    `json:"interface_admin_status"`
	OperStatus     *int    `json:"interface_oper_status"`
	InterfaceType  *int    `json:"interface_type"`
	MACAddress     *string `json:"mac_address"`
	SSID           *string `json:"ssid"`
	BSSID          *string `json:"bssid"`
	Band           *string `json:"band"`
	Frequency      *int    `json:"frequency"`
	NoiseFloor     *int    `json:"noise_floor"`
	ClientCount    *int    `json:"client_count"`
	OverallTxCCQ   *int    `json:"overall_tx_ccq"`
}

type SNMPIPAddress struct {
	InterfaceIndex int     `json:"interface_index"`
	IPAddressCIDR  *string `json:"ip_address"`
	Name           *string `json:"name"`
}

type SNMPReadResult struct {
	Device      SNMPDevice      `json:"device"`
	Interfaces  []SNMPInterface `json:"interfaces"`
	IPAddresses []SNMPIPAddress `json:"ip_addresses"`
}

func snmpSession(cfg Config, host, community string) (*gosnmp.GoSNMP, error) {
	g := &gosnmp.GoSNMP{
		Target:         host,
		Port:           cfg.Port,
		Community:      community,
		Version:        gosnmp.Version2c,
		Timeout:        cfg.Timeout,
		Retries:        cfg.Retries,
		MaxRepetitions: 20,
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

func snmpGetText(g *gosnmp.GoSNMP, oid string) (*string, error) {
	for i := 0; i < snmpAttempts; i++ {
		pkt, err := g.Get([]string{oid})
		if err != nil {
			if i == snmpAttempts-1 {
				return nil, fmt.Errorf("SNMP get failed after %d attempts for %s: %w", snmpAttempts, oid, err)
			}
			continue
		}

		if len(pkt.Variables) == 0 {
			continue
		}

		v := pkt.Variables[0]

		if v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.NoSuchObject {
			continue
		}

		txt := snmpText(v.Value)
		if txt != nil && strings.TrimSpace(*txt) != "" {
			return txt, nil
		}
	}

	return nil, errSNMPEmpty
}

func walkMap(g *gosnmp.GoSNMP, baseOID string) (map[string]gosnmp.SnmpPDU, error) {
	for i := 0; i < snmpAttempts; i++ {
		out := make(map[string]gosnmp.SnmpPDU)

		err := g.BulkWalk(baseOID, func(pdu gosnmp.SnmpPDU) error {
			if pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.NoSuchObject {
				return nil
			}
			suffix := strings.TrimPrefix(pdu.Name, baseOID+".")
			out[suffix] = pdu
			return nil
		})

		if err == nil && len(out) > 0 {
			return out, nil
		}

		if i == snmpAttempts-1 {
			if err != nil {
				return out, fmt.Errorf("SNMP walk failed after %d attempts for %s: %w", snmpAttempts, baseOID, err)
			}
			return out, fmt.Errorf("SNMP walk failed after %d attempts for %s: empty response", snmpAttempts, baseOID)
		}
	}

	return nil, fmt.Errorf("SNMP walk failed for %s", baseOID)
}

func safePDU(m map[string]gosnmp.SnmpPDU, key string) (gosnmp.SnmpPDU, bool) {
	p, ok := m[key]
	if !ok || p.Value == nil {
		return gosnmp.SnmpPDU{}, false
	}
	return p, true
}

func getText(m map[string]gosnmp.SnmpPDU, key string) *string {
	if p, ok := safePDU(m, key); ok {
		return snmpText(p.Value)
	}
	return nil
}

func getInt(m map[string]gosnmp.SnmpPDU, key string) *int {
	if p, ok := safePDU(m, key); ok {
		return snmpInt(p.Value)
	}
	return nil
}

func getMAC(m map[string]gosnmp.SnmpPDU, key string) *string {
	if p, ok := safePDU(m, key); ok {
		return macToString(p.Value)
	}
	return nil
}

func ReadRouterOSSerial(cfg Config, host, community string) (string, error) {
	g, err := snmpSession(cfg, host, community)
	if err != nil {
		return "", err
	}

	defer func() {
		if err := g.Conn.Close(); err != nil {
			log.Printf("SNMP connection termination failed: %v", err)
		}
	}()

	serial, err := snmpGetText(g, ".1.3.6.1.4.1.14988.1.1.7.3.0")
	if err != nil || serial == nil {
		log.Printf("[%s] %v", host, err)
		return "", fmt.Errorf("serial number not found: %w", err)
	}

	return *serial, nil
}

func ReadRouterOS(cfg Config, host, community string) (SNMPReadResult, error) {
	g, err := snmpSession(cfg, host, community)
	if err != nil {
		return SNMPReadResult{}, err
	}

	defer func() {
		if err := g.Conn.Close(); err != nil {
			log.Printf("SNMP connection termination failed: %v", err)
		}
	}()

	serial, err := snmpGetText(g, ".1.3.6.1.4.1.14988.1.1.7.3.0")
	if err != nil || serial == nil {
		log.Printf("[%s] %v", host, err)
		return SNMPReadResult{}, fmt.Errorf("serial number not found: %w", err)
	}

	// optionalGet fetches an OID that may legitimately be absent on some devices.
	// errSNMPEmpty (OID not found / RouterOS null) silently becomes nil.
	// Real transport errors are logged so they are visible but do not fail the read.
	optionalGet := func(oid string) *string {
		v, err := snmpGetText(g, oid)
		if err != nil && !errors.Is(err, errSNMPEmpty) {
			log.Printf("[%s] %v", host, err)
		}
		return v
	}

	name := optionalGet(".1.3.6.1.2.1.1.5.0")
	sysDescr := optionalGet(".1.3.6.1.2.1.1.1.0")
	board := optionalGet(".1.3.6.1.4.1.14988.1.1.7.8.0")
	sw := optionalGet(".1.3.6.1.4.1.14988.1.1.4.4.0")
	fw := optionalGet(".1.3.6.1.4.1.14988.1.1.7.4.0")

	res := SNMPReadResult{
		Device: SNMPDevice{
			Serial:            *serial,
			IP:                host,
			Name:              name,
			SystemDescription: sysDescr,
			BoardName:         board,
			SoftwareVersion:   sw,
			FirmwareVersion:   fw,
		},
	}

	// requireWalk is used for standard MIB tables that must be present on any
	// RouterOS device. The first failure short-circuits remaining calls and the
	// accumulated error is checked once before processing continues.
	var walkErr error
	requireWalk := func(oid string) map[string]gosnmp.SnmpPDU {
		if walkErr != nil {
			return nil
		}
		m, err := walkMap(g, oid)
		if err != nil {
			log.Printf("[%s] %v", host, err)
			walkErr = err
			return nil
		}
		return m
	}

	// INTERFACES
	walkErr = nil

	ifIdxMap := requireWalk(".1.3.6.1.2.1.2.2.1.1") // suffix is index
	ifDescr := requireWalk(".1.3.6.1.2.1.2.2.1.2")
	ifAdmin := requireWalk(".1.3.6.1.2.1.2.2.1.7")
	ifOper := requireWalk(".1.3.6.1.2.1.2.2.1.8")
	ifType := requireWalk(".1.3.6.1.2.1.2.2.1.3")
	ifPhys := requireWalk(".1.3.6.1.2.1.2.2.1.6")
	ifAlias := requireWalk(".1.3.6.1.2.1.31.1.1.1.18")

	if walkErr != nil {
		return SNMPReadResult{}, walkErr
	}

	// Wireless tables are optional — errors are silently ignored because these
	// OIDs do not exist on non-wireless devices and gosnmp reports empty walk
	// as an error, which would be a false positive on every wired device.
	wlAp, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.3.1")   // wireless AP table
	wlStat, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.1.1") // wireless station table
	wl60g, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.8.1")  // wireless 60 GHz table

	// sort interfaces by index
	indexes := make([]int, 0, len(ifIdxMap))
	for _, pdu := range ifIdxMap {
		switch v := pdu.Value.(type) {
		case int:
			indexes = append(indexes, v)
		case int64:
			indexes = append(indexes, int(v))
		case uint32:
			indexes = append(indexes, int(v))
		}
	}
	sort.Ints(indexes)

	res.Interfaces = make([]SNMPInterface, 0, len(indexes))

	// iterate interfaces in order of index
	for _, ifIndex := range indexes {
		idx := strconv.Itoa(ifIndex)

		// Basic interface info
		ifc := SNMPInterface{
			InterfaceIndex: ifIndex,
			Name:           getText(ifDescr, idx),
			AdminStatus:    getInt(ifAdmin, idx),
			OperStatus:     getInt(ifOper, idx),
			InterfaceType:  getInt(ifType, idx),
			MACAddress:     getMAC(ifPhys, idx),
			Comment:        getText(ifAlias, idx),
		}

		// Wireless AP
		if ssid := getText(wlAp, "4."+idx); ssid != nil {
			ifc.SSID = ssid
			ifc.BSSID = getMAC(wlAp, "5."+idx)
			ifc.Band = getText(wlAp, "8."+idx)
			ifc.Frequency = getInt(wlAp, "7."+idx)
			ifc.NoiseFloor = getInt(wlAp, "9."+idx)
			ifc.ClientCount = getInt(wlAp, "6."+idx)
			ifc.OverallTxCCQ = getInt(wlAp, "10."+idx)

			// Wireless station
		} else if ssid := getText(wlStat, "5."+idx); ssid != nil {
			ifc.SSID = ssid
			ifc.BSSID = getMAC(wlStat, "6."+idx)
			ifc.Band = getText(wlStat, "8."+idx)
			ifc.Frequency = getInt(wlStat, "7."+idx)

			// Wireless 60 GHz
		} else if ssid := getText(wl60g, "3."+idx); ssid != nil {
			ifc.SSID = ssid

			if mode := getInt(wl60g, "2."+idx); mode != nil && *mode == 1 {
				ifc.BSSID = getMAC(wl60g, "5."+idx)
			}

			ifc.Frequency = getInt(wl60g, "6."+idx)
		}

		res.Interfaces = append(res.Interfaces, ifc)
	}

	// IP ADDRESSES
	walkErr = nil

	ipAddrs := requireWalk(".1.3.6.1.2.1.4.20.1.1")
	ipMasks := requireWalk(".1.3.6.1.2.1.4.20.1.3")
	ipIfIdx := requireWalk(".1.3.6.1.2.1.4.20.1.2")

	if walkErr != nil {
		return SNMPReadResult{}, walkErr
	}

	for k, pdu := range ipAddrs {
		ipStr := snmpText(pdu.Value)
		if ipStr == nil || net.ParseIP(*ipStr) == nil {
			continue
		}

		m, ok := ipMasks[k]
		if !ok {
			continue
		}

		maskStr := snmpText(m.Value)
		if maskStr == nil || net.ParseIP(*maskStr) == nil {
			continue
		}

		cidr := maskToCIDR(*maskStr)
		if cidr < 0 {
			continue
		}

		ifi, ok := ipIfIdx[k]
		if !ok {
			continue
		}

		ifIndexPtr := snmpInt(ifi.Value)
		if ifIndexPtr == nil {
			continue
		}
		ifIndex := *ifIndexPtr

		cidrStr := fmt.Sprintf("%s/%d", *ipStr, cidr)
		res.IPAddresses = append(res.IPAddresses, SNMPIPAddress{
			InterfaceIndex: ifIndex,
			IPAddressCIDR:  &cidrStr,
			Name:           ipStr,
		})
	}

	return res, nil
}
