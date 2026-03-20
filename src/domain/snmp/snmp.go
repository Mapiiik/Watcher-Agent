package snmp

import (
    "fmt"
    "net"
    "sort"
    "strings"
    "github.com/gosnmp/gosnmp"
)

type SNMPDevice struct {
    Serial            string `json:"serial_number"`
    IP               string `json:"ip_address"`
    Name             string `json:"name"`
    SystemDescription string `json:"system_description"`
    BoardName         string `json:"board_name"`
    SoftwareVersion   string `json:"software_version"`
    FirmwareVersion   string `json:"firmware_version"`
}

type SNMPInterface struct {
    InterfaceIndex       int    `json:"interface_index"`
    Name                 string `json:"name"`
    Comment              string `json:"comment"`
    AdminStatus          int    `json:"interface_admin_status"`
    OperStatus           int    `json:"interface_oper_status"`
    InterfaceType        int    `json:"interface_type"`
    MACAddress           string `json:"mac_address"`
    SSID                 string `json:"ssid"`
    BSSID                string `json:"bssid"`
    Band                 string `json:"band"`
    Frequency            int    `json:"frequency"`
    NoiseFloor           int    `json:"noise_floor"`
    ClientCount          int    `json:"client_count"`
    OverallTxCCQ         int    `json:"overall_tx_ccq"`
}

type SNMPIPAddress struct {
    InterfaceIndex int    `json:"interface_index"`
    IPAddressCIDR  string `json:"ip_address"`
    Name           string `json:"name"`
}

type SNMPReadResult struct {
    Device      SNMPDevice      `json:"device"`
    Interfaces  []SNMPInterface `json:"interfaces"`
    IPAddresses []SNMPIPAddress `json:"ip_addresses"`
}

func snmpSession(cfg Config, host, community string) (*gosnmp.GoSNMP, error) {
    g := &gosnmp.GoSNMP{
        Target:    host,
        Port:      cfg.Port,
        Community: community,
        Version:   gosnmp.Version2c,
        Timeout:   cfg.Timeout,
        Retries:   cfg.Retries,
    }
    if err := g.Connect(); err != nil {
        return nil, err
    }
    return g, nil
}

func snmpGetText(g *gosnmp.GoSNMP, oid string) (string, error) {
    pkt, err := g.Get([]string{oid})
    if err != nil {
        return "", err
    }
    if len(pkt.Variables) == 0 {
        return "", nil
    }
    v := pkt.Variables[0]
    return fmt.Sprintf("%v", v.Value), nil
}

func snmpGetInt(g *gosnmp.GoSNMP, oid string) (int, error) {
    pkt, err := g.Get([]string{oid})
    if err != nil {
        return 0, err
    }
    if len(pkt.Variables) == 0 {
        return 0, nil
    }
    v := pkt.Variables[0]
    switch t := v.Value.(type) {
    case int:
        return t, nil
    case int64:
        return int(t), nil
    case uint:
        return int(t), nil
    case uint32:
        return int(t), nil
    case uint64:
        return int(t), nil
    default:
        return 0, nil
    }
}

func walkMap(g *gosnmp.GoSNMP, baseOID string) (map[string]gosnmp.SnmpPDU, error) {
    out := map[string]gosnmp.SnmpPDU{}
    err := g.Walk(baseOID, func(pdu gosnmp.SnmpPDU) error {
        // store suffix relative to baseOID
        suffix := strings.TrimPrefix(pdu.Name, baseOID+".")
        out[suffix] = pdu
        return nil
    })
    return out, err
}

func ReadRouterOSViaSNMP(cfg Config, host, community string) (SNMPReadResult, error) {
    g, err := snmpSession(cfg, host, community)
    if err != nil {
        return SNMPReadResult{}, err
    }
    defer g.Conn.Close()

    serial, err := snmpGetText(g, ".1.3.6.1.4.1.14988.1.1.7.3.0")
    if err != nil || serial == "" {
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
            Serial:            serial,
            IP:               host,
            Name:             name,
            SystemDescription: sysDescr,
            BoardName:         board,
            SoftwareVersion:   sw,
            FirmwareVersion:   fw,
        },
    }

    // INTERFACES
    ifIdxMap, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1.1") // suffix is index
    ifTable, _ := walkMap(g, ".1.3.6.1.2.1.2.2.1")    // suffix like "2.<idx>" etc
    wlAp, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.3.1")
    wlStat, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.1.1")
    wl60g, _ := walkMap(g, ".1.3.6.1.4.1.14988.1.1.1.8.1")

    indexes := []int{}
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

    for _, ifIndex := range indexes {
        getText := func(key string) string {
            if p, ok := ifTable[key+"."+fmt.Sprint(ifIndex)]; ok {
                return fmt.Sprintf("%v", p.Value)
            }
            return ""
        }
        getInt := func(key string) int {
            if p, ok := ifTable[key+"."+fmt.Sprint(ifIndex)]; ok {
                switch t := p.Value.(type) {
                case int:
                    return t
                case int64:
                    return int(t)
                case uint32:
                    return int(t)
                case uint64:
                    return int(t)
                }
            }
            return 0
        }

        comment, _ := snmpGetText(g, ".1.3.6.1.2.1.31.1.1.1.18."+fmt.Sprint(ifIndex))

        ifc := SNMPInterface{
            InterfaceIndex: ifIndex,
            Name:           getText("2"),
            Comment:        comment,
            AdminStatus:    getInt("7"),
            OperStatus:     getInt("8"),
            InterfaceType:  getInt("3"),
            MACAddress:     macToString(ifTable["6."+fmt.Sprint(ifIndex)].Value),
        }

        // Wireless AP
        if p, ok := wlAp["4."+fmt.Sprint(ifIndex)]; ok && p.Value != nil {
            ifc.SSID = fmt.Sprintf("%v", p.Value)
            ifc.BSSID = macToString(wlAp["5."+fmt.Sprint(ifIndex)].Value)
            ifc.Band = fmt.Sprintf("%v", wlAp["8."+fmt.Sprint(ifIndex)].Value)
            ifc.Frequency = toInt(wlAp["7."+fmt.Sprint(ifIndex)].Value)
            ifc.NoiseFloor = toInt(wlAp["9."+fmt.Sprint(ifIndex)].Value)
            ifc.ClientCount = toInt(wlAp["6."+fmt.Sprint(ifIndex)].Value)
            ifc.OverallTxCCQ = toInt(wlAp["10."+fmt.Sprint(ifIndex)].Value)

        // Wireless station
        } else if p, ok := wlStat["5."+fmt.Sprint(ifIndex)]; ok && p.Value != nil {
            ifc.SSID = fmt.Sprintf("%v", p.Value)
            ifc.BSSID = macToString(wlStat["6."+fmt.Sprint(ifIndex)].Value)
            ifc.Band = fmt.Sprintf("%v", wlStat["8."+fmt.Sprint(ifIndex)].Value)
            ifc.Frequency = toInt(wlStat["7."+fmt.Sprint(ifIndex)].Value)

        // Wireless 60 GHz
        } else if p, ok := wl60g["3."+fmt.Sprint(ifIndex)]; ok && p.Value != nil {
            ifc.SSID = fmt.Sprintf("%v", p.Value)
            // BSSID only for stations (value 1)
            if toInt(wl60g["2."+fmt.Sprint(ifIndex)].Value) == 1 {
                ifc.BSSID = macToString(wl60g["5."+fmt.Sprint(ifIndex)].Value)
            }
            ifc.Frequency = toInt(wl60g["6."+fmt.Sprint(ifIndex)].Value)
        }

        res.Interfaces = append(res.Interfaces, ifc)
    }

    // IP ADDRESSES
    ipAddrs, _ := walkMap(g, ".1.3.6.1.2.1.4.20.1.1")
    ipMasks, _ := walkMap(g, ".1.3.6.1.2.1.4.20.1.3")
    ipIfIdx, _ := walkMap(g, ".1.3.6.1.2.1.4.20.1.2")

    for k, pdu := range ipAddrs {
        ipStr := fmt.Sprintf("%v", pdu.Value)
        if net.ParseIP(ipStr) == nil {
            continue
        }
        m, ok := ipMasks[k]
        if !ok {
            continue
        }
        maskStr := fmt.Sprintf("%v", m.Value)
        if net.ParseIP(maskStr) == nil {
            continue
        }
        cidr := maskToCIDR(maskStr)
        if cidr < 0 {
            continue
        }
        ifi, ok := ipIfIdx[k]
        if !ok {
            continue
        }
        ifIndex := toInt(ifi.Value)

        res.IPAddresses = append(res.IPAddresses, SNMPIPAddress{
            InterfaceIndex: ifIndex,
            IPAddressCIDR:  fmt.Sprintf("%s/%d", ipStr, cidr),
            Name:           ipStr,
        })
    }

    return res, nil
}

func toInt(v any) int {
    switch t := v.(type) {
    case int:
        return t
    case int64:
        return int(t)
    case uint32:
        return int(t)
    case uint64:
        return int(t)
    default:
        return 0
    }
}
