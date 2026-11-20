// Package icmpsocket pings over one ICMP socket for each address family: an unprivileged one where the system allows
// it, a raw one otherwise.
//
// The unprivileged socket (SOCK_DGRAM) needs no right but the group of the process in net.ipv4.ping_group_range,
// which covers IPv6 too and which Docker allows in every container. The kernel gives every request the echo ID of
// the socket and hands the socket only the replies with it, so a reply is found by its sequence number, and no other
// program pinging from the same machine sees it.
//
// The raw socket needs CAP_NET_RAW and gets every ICMP message of the machine, so a filter in the kernel lets only
// echo replies through. Every request gets an echo ID of its own, starting at random, and the reply finds its request
// by it; a reply with that ID from another address or with another sequence number is somebody else's.
//
// Watcher Agent and Watcher Pinger keep this package the same byte for byte, a change goes into both.
package icmpsocket

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Kind is the kind of socket a pinger pings over.
type Kind string

const (
	// Auto takes an unprivileged socket where the system allows it, a raw one otherwise.
	Auto Kind = "auto"
	// Unprivileged is a SOCK_DGRAM socket of ICMP.
	Unprivileged Kind = "unprivileged"
	// Raw is a SOCK_RAW socket, which needs CAP_NET_RAW.
	Raw Kind = "raw"
)

// ParseKind reads a kind from the configuration, empty being Auto.
func ParseKind(s string) (Kind, error) {
	switch k := Kind(s); k {
	case Auto, Unprivileged, Raw:
		return k, nil
	case "":
		return Auto, nil
	}
	return "", fmt.Errorf("unknown kind of ICMP socket %q, one of auto, unprivileged and raw expected", s)
}

// Family is IPv4 or IPv6 with what pinging over it takes.
type Family struct {
	Name string

	v6           bool
	protocol     int
	unprivileged string
	raw          string
	listen       string
	echo, reply  icmp.Type
}

var (
	IPv4 = Family{
		Name: "IPv4", protocol: 1, unprivileged: "udp4", raw: "ip4:icmp", listen: "0.0.0.0",
		echo: ipv4.ICMPTypeEcho, reply: ipv4.ICMPTypeEchoReply,
	}
	IPv6 = Family{
		Name: "IPv6", v6: true, protocol: 58, unprivileged: "udp6", raw: "ip6:ipv6-icmp", listen: "::",
		echo: ipv6.ICMPTypeEchoRequest, reply: ipv6.ICMPTypeEchoReply,
	}
)

// FamilyOf is the family of the address.
func FamilyOf(ip net.IP) Family {
	if ip.To4() != nil {
		return IPv4
	}
	return IPv6
}

const (
	// receiveBuffer is room for a burst of replies while the read loop waits for the CPU. The kernel caps what a
	// socket asks for at net.core.rmem_max, so the host decides how much of it there is.
	receiveBuffer = 4 << 20

	// maxInFlight bounds the requests waiting for a reply at once, the next ones wait for their turn and their time
	// starts only then. It bounds what the buffer has to hold, and keeps a key from being taken twice; Watcher Pinger
	// has as many workers by default.
	maxInFlight = 512
)

// payload tells the requests of Watcher apart in a capture.
var payload = []byte("watcher")

// Pinger shares one socket between the requests waiting at once.
type Pinger struct {
	kind Kind
	fam  Family
	conn net.PacketConn

	mu sync.Mutex
	// waiters are the requests waiting, by their sequence number on an unprivileged socket, by their ID on a raw one
	waiters map[int]chan reply
	key     atomic.Uint32

	// one token for every request between sending and its reply or timeout
	slots chan struct{}
}

// reply is an echo reply as the read loop hands it over.
type reply struct {
	from net.IP
	seq  int
}

// Open opens a socket of the kind for the family, Auto trying an unprivileged one first.
func Open(kind Kind, fam Family) (*Pinger, error) {
	switch kind {
	case Unprivileged, Raw:
		return open(kind, fam)
	case Auto, "":
		p, err := open(Unprivileged, fam)
		if err == nil {
			return p, nil
		}
		p, rawErr := open(Raw, fam)
		if rawErr != nil {
			return nil, fmt.Errorf("neither an unprivileged ICMP socket (%v) nor a raw one (%w)", err, rawErr)
		}
		return p, nil
	}
	return nil, fmt.Errorf("unknown kind of ICMP socket %q, one of auto, unprivileged and raw expected", kind)
}

func open(kind Kind, fam Family) (*Pinger, error) {
	network := fam.unprivileged
	if kind == Raw {
		network = fam.raw
	}

	conn, err := icmp.ListenPacket(network, fam.listen)
	if err != nil {
		return nil, err
	}

	tune(conn, kind, fam)
	p := newPinger(kind, fam, conn, maxInFlight)
	go p.readLoop()
	return p, nil
}

func newPinger(kind Kind, fam Family, conn net.PacketConn, inFlight int) *Pinger {
	p := &Pinger{
		kind:    kind,
		fam:     fam,
		conn:    conn,
		waiters: make(map[int]chan reply),
		slots:   make(chan struct{}, inFlight),
	}
	p.key.Store(rand.Uint32())
	return p
}

// tune asks for the bigger buffer and, on a raw socket, lets only echo replies through. Both are best effort:
// without them pinging still works, only less well under load.
func tune(conn *icmp.PacketConn, kind Kind, fam Family) {
	var under net.PacketConn
	if fam.v6 {
		c := conn.IPv6PacketConn()
		under = c.PacketConn
		if kind == Raw {
			var f ipv6.ICMPFilter
			f.SetAll(true)
			f.Accept(ipv6.ICMPTypeEchoReply)
			_ = c.SetICMPFilter(&f)
		}
	} else {
		c := conn.IPv4PacketConn()
		under = c.PacketConn
		if kind == Raw {
			var f ipv4.ICMPFilter
			f.SetAll(true)
			f.Accept(ipv4.ICMPTypeEchoReply)
			_ = c.SetICMPFilter(&f)
		}
	}

	if c, ok := under.(interface{ SetReadBuffer(int) error }); ok {
		_ = c.SetReadBuffer(receiveBuffer)
	}
}

// Kind is the kind of socket the pinger pings over.
func (p *Pinger) Kind() Kind {
	return p.kind
}

// Close closes the socket; the requests waiting then time out.
func (p *Pinger) Close() error {
	return p.conn.Close()
}

// Ping sends one echo request and waits for its reply. Without one in time ok is false and there is no error: an
// error means the request did not go out.
func (p *Pinger) Ping(ip net.IP, timeout time.Duration) (time.Duration, bool, error) {
	if FamilyOf(ip).v6 != p.fam.v6 {
		return 0, false, fmt.Errorf("%s is not an %s address", ip, p.fam.Name)
	}

	p.slots <- struct{}{}
	defer func() { <-p.slots }()

	// room for a reply that is not ours as well as for ours
	replies := make(chan reply, 4)
	p.mu.Lock()
	key := int(p.key.Add(1) & 0xffff)
	for p.waiters[key] != nil {
		key = int(p.key.Add(1) & 0xffff)
	}
	p.waiters[key] = replies
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, key)
		p.mu.Unlock()
	}()

	// The kernel puts in the ID of an unprivileged socket itself
	id, seq := 0, key
	var to net.Addr = &net.UDPAddr{IP: ip}
	if p.kind == Raw {
		id = key
		to = &net.IPAddr{IP: ip}
	}

	request, err := (&icmp.Message{
		Type: p.fam.echo,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
	}).Marshal(nil)
	if err != nil {
		return 0, false, err
	}

	start := time.Now()
	if _, err := p.conn.WriteTo(request, to); err != nil {
		return 0, false, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	if !await(replies, timer.C, ip, seq) {
		return 0, false, nil
	}
	return time.Since(start), true, nil
}

// await waits for the reply from the address with the sequence number, passing over the replies that are somebody
// else's, until the time is up.
func await(replies <-chan reply, timeUp <-chan time.Time, from net.IP, seq int) bool {
	for {
		select {
		case r := <-replies:
			if r.from.Equal(from) && r.seq == seq {
				return true
			}
		case <-timeUp:
			return false
		}
	}
}

// readLoop hands every echo reply to the request waiting for it and drops the rest, until the socket is closed.
func (p *Pinger) readLoop() {
	buf := make([]byte, 1500)

	for {
		n, peer, err := p.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// the replies of a passing failure are lost, the pinger stays
			time.Sleep(10 * time.Millisecond)
			continue
		}

		var from net.IP
		switch addr := peer.(type) {
		case *net.IPAddr:
			from = addr.IP
		case *net.UDPAddr:
			from = addr.IP
		default:
			continue
		}

		message, err := icmp.ParseMessage(p.fam.protocol, buf[:n])
		if err != nil || message.Type != p.fam.reply {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		key := echo.Seq
		if p.kind == Raw {
			key = echo.ID
		}
		p.mu.Lock()
		replies, ok := p.waiters[key]
		p.mu.Unlock()
		if !ok {
			continue
		}

		select {
		case replies <- reply{from: from, seq: echo.Seq}:
		default:
		}
	}
}
