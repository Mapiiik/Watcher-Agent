package main

import (
	"log"
	"net"

	"github.com/pires/go-proxyproto"
)

// newProxyListener uses the PROXY header only from the given networks and lets it be missing there. From anywhere
// else the header is dropped and the connection keeps its real address. Without any network the header is used from
// everybody, which installations from before the list rely on.
func newProxyListener(ln net.Listener, allowCIDRs []string) net.Listener {
	if len(allowCIDRs) == 0 {
		log.Println("WARNING: AGENT_PROXY_ALLOW_CIDRS is not set, anybody who reaches this port can claim any address")
		return &proxyproto.Listener{Listener: ln}
	}

	return &proxyproto.Listener{
		Listener: ln,
		ConnPolicy: func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			host, _, err := net.SplitHostPort(opts.Upstream.String())
			if err == nil && ipAllowed(host, allowCIDRs) {
				return proxyproto.USE, nil
			}
			return proxyproto.IGNORE, nil
		},
	}
}
