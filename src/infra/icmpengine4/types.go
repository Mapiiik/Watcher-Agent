package icmpengine4

import (
	"net"
)

// reply is an echo reply as the read loop hands it over
type reply struct {
	from net.IP
	id   int
	seq  int
}

// waiter is a ping waiting for the reply with its ID
type waiter struct {
	ch chan reply
}
