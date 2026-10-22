package snmp

import (
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"golang.org/x/text/encoding/charmap"

	"watcher-agent/src/testutil/snmpagent"
)

const community = "test-community"

func agentConfig(a *snmpagent.Agent) Config {
	return Config{Port: a.Port, Timeout: 500 * time.Millisecond, Retries: 0}
}

func cp1250(t *testing.T, s string) []byte {
	t.Helper()
	b, err := charmap.Windows1250.NewEncoder().String(s)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(b)
}

func system(t *testing.T) []gosnmp.SnmpPDU {
	return []gosnmp.SnmpPDU{
		snmpagent.Text(".1.3.6.1.4.1.14988.1.1.7.3.0", []byte("HE408XYZ123")),
		snmpagent.Text(".1.3.6.1.2.1.1.5.0", cp1250(t, "Kancelář")),
		snmpagent.Text(".1.3.6.1.2.1.1.1.0", []byte("RouterOS RB5009UG+S+")),
		snmpagent.Text(".1.3.6.1.4.1.14988.1.1.7.8.0", []byte("RB5009UG+S+")),
		snmpagent.Text(".1.3.6.1.4.1.14988.1.1.4.4.0", []byte("7.23.5")),
	}
}

// One wired interface, a wireless AP, a wireless station and two 60 GHz interfaces (one of them a
// station, so without BSSID), plus their addresses. Index 10 checks that interfaces sort numerically.
func routerOS(t *testing.T) []gosnmp.SnmpPDU {
	mac := []byte{0x4c, 0x5e, 0x0c, 0x01, 0x02, 0x03}
	pdus := system(t)

	for _, ifc := range []struct {
		index       int
		name, alias string
		ifType      int
	}{
		{1, "ether1", "Uplink", 6},
		{2, "wlan1", "", 71},
		{3, "wlan2", "", 71},
		{10, "wlan60-1", "", 71},
		{11, "wlan60-2", "", 71},
	} {
		i := strconv.Itoa(ifc.index)
		pdus = append(pdus,
			snmpagent.Int(".1.3.6.1.2.1.2.2.1.1."+i, ifc.index),
			snmpagent.Text(".1.3.6.1.2.1.2.2.1.2."+i, []byte(ifc.name)),
			snmpagent.Int(".1.3.6.1.2.1.2.2.1.3."+i, ifc.ifType),
			snmpagent.Text(".1.3.6.1.2.1.2.2.1.6."+i, mac),
			snmpagent.Int(".1.3.6.1.2.1.2.2.1.7."+i, 1),
			snmpagent.Int(".1.3.6.1.2.1.2.2.1.8."+i, 2),
			snmpagent.Text(".1.3.6.1.2.1.31.1.1.1.18."+i, []byte(ifc.alias)),
		)
	}

	ap := ".1.3.6.1.4.1.14988.1.1.1.3.1."
	station := ".1.3.6.1.4.1.14988.1.1.1.1.1."
	w60g := ".1.3.6.1.4.1.14988.1.1.1.8.1."
	bssid := []byte{0xd4, 0x01, 0xc3, 0xaa, 0xbb, 0xcc}

	pdus = append(pdus,
		snmpagent.Text(ap+"4.2", []byte("NETAIR-AP")),
		snmpagent.Text(ap+"5.2", bssid),
		snmpagent.Gauge(ap+"6.2", 12),
		snmpagent.Int(ap+"7.2", 5180),
		snmpagent.Text(ap+"8.2", []byte("5ghz-a/n/ac")),
		snmpagent.Int(ap+"9.2", -105),
		snmpagent.Int(ap+"10.2", 87),

		snmpagent.Text(station+"5.3", []byte("NETAIR-PTP")),
		snmpagent.Text(station+"6.3", bssid),
		snmpagent.Int(station+"7.3", 5500),
		snmpagent.Text(station+"8.3", []byte("5ghz-a/n")),

		snmpagent.Int(w60g+"2.10", 1),
		snmpagent.Text(w60g+"3.10", []byte("NETAIR-60G")),
		snmpagent.Text(w60g+"5.10", bssid),
		snmpagent.Int(w60g+"6.10", 60480),
		snmpagent.Int(w60g+"2.11", 0),
		snmpagent.Text(w60g+"3.11", []byte("NETAIR-60G")),
		snmpagent.Text(w60g+"5.11", bssid),
		snmpagent.Int(w60g+"6.11", 60480),
	)

	for _, a := range []struct {
		ip, mask string
		index    int
	}{
		{"192.168.88.1", "255.255.255.0", 1},
		{"10.10.0.2", "255.255.255.252", 3},
		{"192.168.99.1", "255.0.255.0", 1}, // not a valid mask, skipped
	} {
		pdus = append(pdus,
			snmpagent.IP(".1.3.6.1.2.1.4.20.1.1."+a.ip, a.ip),
			snmpagent.Int(".1.3.6.1.2.1.4.20.1.2."+a.ip, a.index),
			snmpagent.IP(".1.3.6.1.2.1.4.20.1.3."+a.ip, a.mask),
		)
	}

	return pdus
}

func TestReadRouterOSSerial(t *testing.T) {
	a := snmpagent.Start(t, community, system(t))

	serial, err := ReadRouterOSSerial(agentConfig(a), "127.0.0.1", community)
	if err != nil {
		t.Fatal(err)
	}
	if serial != "HE408XYZ123" {
		t.Errorf("serial = %q, want HE408XYZ123", serial)
	}
}

func TestReadRouterOSSerialMissing(t *testing.T) {
	a := snmpagent.Start(t, community, system(t)[1:])

	_, err := ReadRouterOSSerial(agentConfig(a), "127.0.0.1", community)
	if !errors.Is(err, errSNMPEmpty) {
		t.Fatalf("err = %v, want errSNMPEmpty", err)
	}
}

func TestReadRouterOSSerialWrongCommunity(t *testing.T) {
	a := snmpagent.Start(t, community, system(t))
	cfg := agentConfig(a)
	cfg.Timeout = 50 * time.Millisecond

	if _, err := ReadRouterOSSerial(cfg, "127.0.0.1", "public"); err == nil {
		t.Fatal("a device that ignores the community gave a serial")
	}
}

func TestReadRouterOS(t *testing.T) {
	a := snmpagent.Start(t, community, routerOS(t))

	res, err := ReadRouterOS(agentConfig(a), "127.0.0.1", community)
	if err != nil {
		t.Fatal(err)
	}

	d := res.Device
	if d.Serial != "HE408XYZ123" || d.IP != "127.0.0.1" {
		t.Errorf("device = %s at %s", d.Serial, d.IP)
	}
	checkText(t, "name", d.Name, "Kancelář")
	checkText(t, "system description", d.SystemDescription, "RouterOS RB5009UG+S+")
	checkText(t, "board", d.BoardName, "RB5009UG+S+")
	checkText(t, "software", d.SoftwareVersion, "7.23.5")
	if d.FirmwareVersion != nil {
		t.Errorf("firmware = %q, want nil (not on the device)", *d.FirmwareVersion)
	}

	var indexes []int
	for _, ifc := range res.Interfaces {
		indexes = append(indexes, ifc.InterfaceIndex)
	}
	if !slices.Equal(indexes, []int{1, 2, 3, 10, 11}) {
		t.Fatalf("interfaces = %v, want [1 2 3 10 11]", indexes)
	}

	ether, ap, station, w60, w60station := res.Interfaces[0], res.Interfaces[1], res.Interfaces[2], res.Interfaces[3], res.Interfaces[4]

	checkText(t, "ether1 name", ether.Name, "ether1")
	checkText(t, "ether1 comment", ether.Comment, "Uplink")
	checkText(t, "ether1 MAC", ether.MACAddress, "4c:5e:0c:01:02:03")
	checkInt(t, "ether1 type", ether.InterfaceType, 6)
	checkInt(t, "ether1 admin", ether.AdminStatus, 1)
	checkInt(t, "ether1 oper", ether.OperStatus, 2)
	if ether.SSID != nil || ether.Frequency != nil {
		t.Errorf("ether1 has wireless data: %v %v", ether.SSID, ether.Frequency)
	}
	if ap.Comment != nil {
		t.Errorf("wlan1 comment = %q, want nil for an empty alias", *ap.Comment)
	}

	checkText(t, "AP SSID", ap.SSID, "NETAIR-AP")
	checkText(t, "AP BSSID", ap.BSSID, "d4:01:c3:aa:bb:cc")
	checkText(t, "AP band", ap.Band, "5ghz-a/n/ac")
	checkInt(t, "AP frequency", ap.Frequency, 5180)
	checkInt(t, "AP noise floor", ap.NoiseFloor, -105)
	checkInt(t, "AP clients", ap.ClientCount, 12)
	checkInt(t, "AP CCQ", ap.OverallTxCCQ, 87)

	checkText(t, "station SSID", station.SSID, "NETAIR-PTP")
	checkText(t, "station BSSID", station.BSSID, "d4:01:c3:aa:bb:cc")
	checkText(t, "station band", station.Band, "5ghz-a/n")
	checkInt(t, "station frequency", station.Frequency, 5500)
	if station.ClientCount != nil {
		t.Errorf("station clients = %d, want nil", *station.ClientCount)
	}

	checkText(t, "60 GHz SSID", w60.SSID, "NETAIR-60G")
	checkText(t, "60 GHz BSSID", w60.BSSID, "d4:01:c3:aa:bb:cc")
	checkInt(t, "60 GHz frequency", w60.Frequency, 60480)
	if w60station.BSSID != nil {
		t.Errorf("60 GHz station BSSID = %q, want nil (mode 0)", *w60station.BSSID)
	}

	got := map[string]int{}
	for _, ip := range res.IPAddresses {
		got[deref(ip.IPAddressCIDR)] = ip.InterfaceIndex
		if ip.Name == nil {
			t.Errorf("address %s has no name", deref(ip.IPAddressCIDR))
		}
	}
	want := map[string]int{"192.168.88.1/24": 1, "10.10.0.2/30": 3}
	if len(got) != len(want) || got["192.168.88.1/24"] != 1 || got["10.10.0.2/30"] != 3 {
		t.Errorf("addresses = %v, want %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
	}
}

func TestReadRouterOSFailsWithoutAnInterfaceTable(t *testing.T) {
	var pdus []gosnmp.SnmpPDU
	for _, p := range routerOS(t) {
		if !strings.HasPrefix(p.Name, ".1.3.6.1.2.1.31.1.1.1.18.") {
			pdus = append(pdus, p)
		}
	}
	a := snmpagent.Start(t, community, pdus)

	if _, err := ReadRouterOS(agentConfig(a), "127.0.0.1", community); err == nil {
		t.Fatal("read succeeded without ifAlias")
	}
}

func checkText(t *testing.T, what string, got *string, want string) {
	t.Helper()
	if got == nil || *got != want {
		t.Errorf("%s = %s, want %q", what, deref(got), want)
	}
}

func checkInt(t *testing.T, what string, got *int, want int) {
	t.Helper()
	if got == nil || *got != want {
		if got == nil {
			t.Errorf("%s = nil, want %d", what, want)
		} else {
			t.Errorf("%s = %d, want %d", what, *got, want)
		}
	}
}
