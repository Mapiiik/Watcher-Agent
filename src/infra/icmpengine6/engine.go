package icmpengine6

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type Engine struct {
	mu       sync.Mutex
	conn     *icmp.PacketConn
	waiters  map[int]*waiter
	refCount int
	stopCh   chan struct{}
}

var (
	engine     *Engine
	engineOnce sync.Once
	globalID   uint32
)

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
		conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return err
		}
		e.conn = conn
		e.stopCh = make(chan struct{})
		go e.readLoop()
	}

	e.refCount++
	return nil
}

func (e *Engine) Release() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.refCount--
	if e.refCount == 0 {
		close(e.stopCh)
		_ = e.conn.Close()
		e.conn = nil
	}
}

func (e *Engine) nextID() int {
	return int(atomic.AddUint32(&globalID, 1) & 0xffff)
}

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
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("watcher"),
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
		if !r.from.Equal(ip) {
			return 0, false, errors.New("reply from unexpected IP")
		}
		if r.seq != seq {
			return 0, false, errors.New("seq mismatch")
		}
		return time.Since(start), true, nil

	case <-time.After(timeout):
		return 0, false, nil
	}
}
