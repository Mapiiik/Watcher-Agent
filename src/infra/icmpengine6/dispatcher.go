package icmpengine6

import (
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// readLoop hands every echo reply on conn to the ping waiting for its ID and drops the rest, until conn is closed.
// Acquire may open the next connection before this loop notices, so it works with its own and never with e.conn.
func (e *Engine) readLoop(conn *icmp.PacketConn) {
	buf := make([]byte, 1500)

	for {
		n, peer, err := conn.ReadFrom(buf)
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
