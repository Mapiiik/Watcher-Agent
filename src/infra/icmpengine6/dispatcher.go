package icmpengine6

import (
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func (e *Engine) readLoop() {
	buf := make([]byte, 1500)

	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		n, peer, err := e.conn.ReadFrom(buf)
		if err != nil {
			return
		}

		peerAddr, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}

		rm, err := icmp.ParseMessage(58, buf[:n])
		if err != nil || rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}

		body, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		e.mu.Lock()
		w, ok := e.waiters[body.ID]
		e.mu.Unlock()

		if !ok {
			continue
		}

		select {
		case w.ch <- reply{
			from: peerAddr.IP,
			id:   body.ID,
			seq:  body.Seq,
		}:
		default:
		}
	}
}
