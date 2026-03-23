package icmpengine4

import (
	"net"
)

// reply - internal representation of ICMP EchoReply
type reply struct {
	from net.IP
	id   int
	seq  int
}

// waiter - represents a waiting ping request
type waiter struct {
	ch chan reply
}
