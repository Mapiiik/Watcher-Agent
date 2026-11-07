package icmpengine6

import (
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
)

var (
	loopback  = net.ParseIP("::1")
	elsewhere = net.ParseIP("2001:db8::1")
)

// Pings that open and close the socket between them, so that a read loop is still running when the next one starts.
// Run with -race; opening a raw socket takes root or CAP_NET_RAW, without it the test is skipped.
func TestSocketOpensAndClosesAmongPings(t *testing.T) {
	e := &Engine{waiters: make(map[int]*waiter)}
	if err := e.Acquire(); err != nil {
		t.Skipf("no raw socket: %v", err)
	}
	e.Release()

	var pings sync.WaitGroup
	for range 4 {
		pings.Go(func() {
			for seq := range 50 {
				if err := e.Acquire(); err != nil {
					t.Error(err)
					return
				}
				_, ok, err := e.Ping(loopback, seq, time.Second)
				e.Release()
				if !ok || err != nil {
					t.Errorf("ping %d: %v, %v", seq, ok, err)
				}
			}
		})
	}
	pings.Wait()
}

// A reply that is not the ping's own is no reply, and not a failure to send.
func TestPingTakesAReplyNotItsOwnForNone(t *testing.T) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		t.Skipf("no raw socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Without a read loop only what the test hands over comes back
	e := &Engine{conn: conn, waiters: make(map[int]*waiter)}

	for name, r := range map[string]reply{
		"another address":         {from: elsewhere, seq: 1},
		"another sequence number": {from: loopback, seq: 2},
	} {
		type answer struct {
			ok  bool
			err error
		}
		answered := make(chan answer, 1)
		go func() {
			_, ok, err := e.Ping(loopback, 1, 10*time.Second)
			answered <- answer{ok, err}
		}()

		handOver(t, e, r)

		if got := <-answered; got.ok || got.err != nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// handOver gives the reply to the ping as soon as there is one waiting.
func handOver(t *testing.T, e *Engine, r reply) {
	t.Helper()

	for range 1000 {
		e.mu.Lock()
		for _, w := range e.waiters {
			w.ch <- r
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no ping is waiting")
}
