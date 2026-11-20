package icmpsocket

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	kinds    = []Kind{Unprivileged, Raw}
	families = []Family{IPv4, IPv6}
)

// opened opens a socket of the kind, or skips a test run where the system does not allow it. IPv6 also needs ::1,
// which a container without IPv6 does not have.
func opened(t *testing.T, kind Kind, fam Family) *Pinger {
	t.Helper()
	if fam.v6 {
		ln, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			t.Skipf("no ::1 here: %v", err)
		}
		_ = ln.Close()
	}
	p, err := Open(kind, fam)
	if err != nil {
		t.Skipf("no %s %s ICMP socket here: %v", kind, fam.Name, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func loopback(fam Family) net.IP {
	if fam.v6 {
		return net.IPv6loopback
	}
	return net.IPv4(127, 0, 0, 1)
}

func TestTheLoopbackAnswers(t *testing.T) {
	for _, fam := range families {
		for _, kind := range kinds {
			t.Run(fam.Name+" "+string(kind), func(t *testing.T) {
				p := opened(t, kind, fam)

				rtt, ok, err := p.Ping(loopback(fam), time.Second)
				if err != nil || !ok {
					t.Fatalf("ok %v, err %v", ok, err)
				}
				// Windows may measure the loopback as no time at all
				if rtt < 0 || rtt > time.Second {
					t.Errorf("round trip %v", rtt)
				}
			})
		}
	}
}

// Requests waiting at once each get their own reply.
func TestRequestsAtOnceTakeTheirOwnReplies(t *testing.T) {
	for _, fam := range families {
		for _, kind := range kinds {
			t.Run(fam.Name+" "+string(kind), func(t *testing.T) {
				p := opened(t, kind, fam)

				var wg sync.WaitGroup
				failed := make(chan string, 64)
				for i := range 64 {
					ip := loopback(fam)
					if !fam.v6 {
						ip = net.IPv4(127, 0, 0, byte(1+i))
					}
					wg.Go(func() {
						if _, ok, err := p.Ping(ip, 2*time.Second); err != nil || !ok {
							failed <- ip.String()
						}
					})
				}
				wg.Wait()
				close(failed)

				for ip := range failed {
					t.Errorf("%s did not answer", ip)
				}
			})
		}
	}
}

// Two pingers on one machine do not take each other's replies, which a raw socket sees too: with the same keys,
// two programs counting from the same place, each passes over the replies to the addresses of the other.
func TestTwoPingersKeepToTheirOwnReplies(t *testing.T) {
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			pingers := []*Pinger{opened(t, kind, IPv4), opened(t, kind, IPv4)}
			pingers[1].key.Store(pingers[0].key.Load())

			var wg sync.WaitGroup
			failed := make(chan string, 128)
			for n, p := range pingers {
				for i := range 64 {
					ip := net.IPv4(127, byte(1+n), 0, byte(1+i))
					wg.Go(func() {
						if _, ok, err := p.Ping(ip, 2*time.Second); err != nil || !ok {
							failed <- ip.String()
						}
					})
				}
			}
			wg.Wait()
			close(failed)

			lost := 0
			for range failed {
				lost++
			}
			if lost > 0 {
				t.Errorf("%d of 128 requests got no reply of their own", lost)
			}
		})
	}
}

// A raw socket lets only echo replies through, the rest of ICMP stays in the kernel. Only Linux has the filter.
func TestARawSocketTakesOnlyEchoReplies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the ICMP filter is Linux's")
	}
	p := opened(t, Raw, IPv4).conn.(*icmp.PacketConn)
	f4, err := p.IPv4PacketConn().ICMPFilter()
	if err != nil {
		t.Fatal(err)
	}
	if f4.WillBlock(ipv4.ICMPTypeEchoReply) || !f4.WillBlock(ipv4.ICMPTypeEcho) ||
		!f4.WillBlock(ipv4.ICMPTypeDestinationUnreachable) {
		t.Errorf("IPv4 filter %+v", f4)
	}

	p = opened(t, Raw, IPv6).conn.(*icmp.PacketConn)
	f6, err := p.IPv6PacketConn().ICMPFilter()
	if err != nil {
		t.Fatal(err)
	}
	if f6.WillBlock(ipv6.ICMPTypeEchoReply) || !f6.WillBlock(ipv6.ICMPTypeEchoRequest) ||
		!f6.WillBlock(ipv6.ICMPTypeNeighborAdvertisement) {
		t.Errorf("IPv6 filter %+v", f6)
	}
}

// A reply that is somebody else's is passed over, and the request waits on for its own.
func TestAReplyOfSomebodyElseIsPassedOver(t *testing.T) {
	replies := make(chan reply, 4)
	ip := net.ParseIP("192.0.2.1").To4()
	replies <- reply{from: net.ParseIP("192.0.2.9").To4(), seq: 7}
	replies <- reply{from: ip, seq: 8}
	replies <- reply{from: ip, seq: 7}

	if !await(replies, time.After(time.Second), ip, 7) {
		t.Error("the own reply was not taken")
	}

	replies <- reply{from: ip, seq: 8}
	if await(replies, time.After(50*time.Millisecond), ip, 7) {
		t.Error("a reply of somebody else was taken")
	}
}

// An address nobody has is not answered, and that is no error.
func TestAnAddressNobodyHasIsNotAnswered(t *testing.T) {
	p := opened(t, Auto, IPv4)

	// TEST-NET-1, never routed
	_, ok, err := p.Ping(net.ParseIP("192.0.2.1"), 200*time.Millisecond)
	if ok {
		t.Error("192.0.2.1 answered")
	}
	if err != nil {
		// a machine without a default route cannot send it at all
		t.Logf("not sent: %v", err)
	}
}

// An address of the other family is an error rather than an address down.
func TestAnAddressOfTheOtherFamilyIsAnError(t *testing.T) {
	for fam, ip := range map[Family]string{IPv4: "2001:db8::1", IPv6: "192.0.2.1"} {
		p := &Pinger{fam: fam}
		if _, ok, err := p.Ping(net.ParseIP(ip), time.Second); err == nil || ok {
			t.Errorf("%s over %s: ok %v, err %v", ip, fam.Name, ok, err)
		}
	}
}

func TestKinds(t *testing.T) {
	for in, want := range map[string]Kind{"": Auto, "auto": Auto, "unprivileged": Unprivileged, "raw": Raw} {
		if got, err := ParseKind(in); got != want || err != nil {
			t.Errorf("ParseKind(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"icmpv5", "Raw", " raw"} {
		if _, err := ParseKind(bad); err == nil {
			t.Errorf("ParseKind(%q) passed", bad)
		}
	}
	if _, err := Open("icmpv5", IPv4); err == nil {
		t.Error("an unknown kind opened")
	}
}

// silentConn takes every echo request, notes its sequence number and answers none, so no socket is needed.
type silentConn struct {
	net.PacketConn

	mu   sync.Mutex
	seqs []int
}

func (c *silentConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if m, err := icmp.ParseMessage(IPv4.protocol, b); err == nil {
		if echo, ok := m.Body.(*icmp.Echo); ok {
			c.mu.Lock()
			c.seqs = append(c.seqs, echo.Seq)
			c.mu.Unlock()
		}
	}
	return len(b), nil
}

func (c *silentConn) sent() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.seqs...)
}

// More requests than slots: the rest wait for their turn, and waiting is not losing.
func TestRequestsBeyondTheSlotsWaitForTheirTurn(t *testing.T) {
	conn := &silentConn{}
	p := newPinger(Unprivileged, IPv4, conn, 4)

	var peak atomic.Int64
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		for {
			p.mu.Lock()
			n := int64(len(p.waiters))
			p.mu.Unlock()
			if n > peak.Load() {
				peak.Store(n)
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	var pings sync.WaitGroup
	for range 12 {
		pings.Go(func() {
			if _, ok, err := p.Ping(net.ParseIP("192.0.2.1"), 30*time.Millisecond); ok || err != nil {
				t.Errorf("ping: %v, %v", ok, err)
			}
		})
	}
	pings.Wait()
	close(stop)
	<-watched

	if n := len(conn.sent()); n != 12 {
		t.Errorf("%d requests sent", n)
	}
	if n := peak.Load(); n > 4 {
		t.Errorf("%d requests waiting for a reply at once", n)
	}
}

// A key a request still waits with is not handed out again, the new request would take its reply and its place.
func TestAKeyStillWaitingIsSkipped(t *testing.T) {
	conn := &silentConn{}
	p := newPinger(Unprivileged, IPv4, conn, maxInFlight)
	p.key.Store(99)
	waiting := make(chan reply, 4)
	p.waiters[100] = waiting

	if _, ok, err := p.Ping(net.ParseIP("192.0.2.1"), time.Millisecond); ok || err != nil {
		t.Fatalf("ping: %v, %v", ok, err)
	}

	if seqs := conn.sent(); len(seqs) != 1 || seqs[0] != 101 {
		t.Errorf("sent with sequence numbers %v", seqs)
	}
	if p.waiters[100] != waiting {
		t.Error("the waiting request lost its place")
	}
}
