package icmpsocket

import (
	"net"
	"strings"
	"testing"
	"time"
)

// Each address goes over the socket of its family.
func TestPingersPingEachFamily(t *testing.T) {
	ps, err := OpenPingers(Auto, nil)
	if err != nil {
		t.Skipf("no ICMP socket here: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })

	for _, fam := range families {
		if _, err := ps.Socket(fam); err != nil {
			t.Logf("no %s socket here: %v", fam.Name, err)
			continue
		}
		if fam.v6 {
			if ln, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
				t.Logf("no ::1 here: %v", err)
				continue
			} else {
				_ = ln.Close()
			}
		}
		if _, ok, err := ps.Ping(loopback(fam), time.Second); !ok || err != nil {
			t.Errorf("%s loopback: ok %v, err %v", fam.Name, ok, err)
		}
	}
}

// A family whose socket could not be opened answers with the error for a minute, then it is tried again.
func TestPingersTryAFailedFamilyAgainAfterAMinute(t *testing.T) {
	var reports []string
	ps, err := OpenPingers("icmpv5", func(fam Family, p *Pinger, err error) {
		reports = append(reports, fam.Name+" "+map[bool]string{true: "opened", false: "failed"}[err == nil])
	})
	if err == nil {
		t.Fatal("an unknown kind opened")
	}
	if got := strings.Join(reports, ", "); got != "IPv4 failed, IPv6 failed" {
		t.Errorf("reports %q", got)
	}
	if got := ps.Describe(); got != "IPv4 none, IPv6 none" {
		t.Errorf("Describe() = %q", got)
	}
	if _, ok, err := ps.Ping(net.ParseIP("127.0.0.1"), time.Second); ok || err == nil ||
		!strings.Contains(err.Error(), "no IPv4 ICMP socket") {
		t.Errorf("ping: ok %v, err %v", ok, err)
	}

	// Within the minute the socket is not tried, even where it would open now
	ps.kind = Auto
	if _, err := ps.Socket(IPv4); err == nil {
		t.Error("tried again within the minute")
	}

	ps.mu.Lock()
	ps.tried[IPv4.Name] = time.Now().Add(-2 * retryAfter)
	ps.mu.Unlock()
	if _, err := ps.Socket(IPv4); err != nil {
		t.Skipf("no ICMP socket here: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	if !strings.HasPrefix(ps.Describe(), "IPv4 unprivileged") && !strings.HasPrefix(ps.Describe(), "IPv4 raw") {
		t.Errorf("Describe() = %q", ps.Describe())
	}
	if last := reports[len(reports)-1]; last != "IPv4 opened" {
		t.Errorf("last report %q", last)
	}
}
