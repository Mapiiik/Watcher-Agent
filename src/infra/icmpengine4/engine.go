// Package icmpengine4 pings IPv4 hosts over a shared raw socket, which needs CAP_NET_RAW.
package icmpengine4

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Engine shares one raw ICMP socket between concurrent pings: the first Acquire opens it, the last Release
// closes it, and replies find their ping by the echo ID.
type Engine struct {
	mu       sync.Mutex
	conn     *icmp.PacketConn
	waiters  map[int]*waiter
	refCount int
}

var (
	engine     *Engine
	engineOnce sync.Once
	globalID   uint32
)

// Get returns the engine of the process.
func Get() *Engine {
	engineOnce.Do(func() {
		engine = &Engine{
			waiters: make(map[int]*waiter),
		}
	})
	return engine
}

func (e *Engine) Acquire() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.refCount == 0 {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return err
		}
		e.conn = conn
		go e.readLoop(conn)
	}

	e.refCount++
	return nil
}

func (e *Engine) Release() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.refCount--
	if e.refCount == 0 {
		_ = e.conn.Close()
		e.conn = nil
	}
}

func (e *Engine) nextID() int {
	return int(atomic.AddUint32(&globalID, 1) & 0xffff)
}

// Ping sends one echo request and waits for its reply. Without one in time, or with one that is not its own, ok is
// false and there is no error: an error means the request did not go out.
func (e *Engine) Ping(ip net.IP, seq int, timeout time.Duration) (time.Duration, bool, error) {
	id := e.nextID()

	w := &waiter{
		ch: make(chan reply, 1),
	}

	e.mu.Lock()
	e.waiters[id] = w
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		delete(e.waiters, id)
		e.mu.Unlock()
	}()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("watcher-agent"),
		},
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, false, err
	}

	start := time.Now()

	if _, err := e.conn.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
		return 0, false, err
	}

	select {
	case r := <-w.ch:
		if !r.from.Equal(ip) || r.seq != seq {
			return 0, false, nil
		}
		return time.Since(start), true, nil

	case <-time.After(timeout):
		return 0, false, nil
	}
}
