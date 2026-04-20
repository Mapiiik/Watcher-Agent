package snmp

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

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
	const attempts = 3

	for i := 0; i < attempts; i++ {
		pkt, err := g.Get([]string{oid})
		if err != nil {
			if i == attempts-1 {
				return nil, fmt.Errorf("SNMP get failed for %s: %w", oid, err)
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

	return nil, fmt.Errorf("SNMP get returned empty value for %s after retries", oid)
}

func walkMap(g *gosnmp.GoSNMP, baseOID string) (map[string]gosnmp.SnmpPDU, error) {
	const attempts = 3

	for i := 0; i < attempts; i++ {
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

		if i == attempts-1 {
			return out, fmt.Errorf("SNMP walk failed for %s: %w", baseOID, err)
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
	if err != nil {
		return "", err
	}
	if serial == nil || strings.TrimSpace(*serial) == "" {
		return "", fmt.Errorf("serial not found")
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
		if err == nil {
			err = fmt.Errorf("serial not found")
		}
		return SNMPReadResult{}, err
	}

	name, _ := snmpGetText(g, ".1.3.6.1.2.1.1.5.0")
	sysDescr, _ := snmpGetText(g, ".1.3.6.1.2.1.1.1.0")
	board, _ := snmpGetText(g, ".1.3.6.1.4.1.14988.1.1.7.8.0")
	sw, _ := snmpGetText(g, ".1.3.6.1.4.1.14988.1.1.4.4.0")
	fw, _ := snmpGetText(g, ".1.3.6.1.4.1.14988.1.1.7.4.0")

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

	// INTERFACES

	// interface indexes
	ifIdxMap, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1.1") // suffix is index
	// required for basic info (ifTable)
	ifDescr, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1.2")
	ifAdmin, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1.7")
	ifOper, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1.8")
	ifType, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1.3")
	ifPhys, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1.6")
	// interface aliases (comments)
	ifAlias, _ := walkMap(g, ".1.3.6.1.2.1.31.1.1.1.18")

	// optional wireless AP table
	wlAp, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.3.1")
	// optional wireless station table
	wlStat, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.1.1")
	// optional wireless 60 GHz table
	wl60g, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.8.1")

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
	ipAddrs, _ := walkMap(g, ".1.3.6.1.2.1.4.20.1.1")
	ipMasks, _ := walkMap(g, ".1.3.6.1.2.1.4.20.1.3")
	ipIfIdx, _ := walkMap(g, ".1.3.6.1.2.1.4.20.1.2")

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
