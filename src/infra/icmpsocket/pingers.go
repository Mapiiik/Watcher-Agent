package icmpsocket

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// retryAfter is how long a family whose socket could not be opened answers with that error before the next try.
const retryAfter = time.Minute

// Pingers pings every address over the socket of its family. Each socket is kept once open; one that could not be
// opened is tried again a minute later, and until then its requests fail with the error.
type Pingers struct {
	kind Kind
	// report hears of every socket opened and of the first failure of a family, for the log
	report func(fam Family, p *Pinger, err error)

	mu      sync.Mutex
	sockets map[string]*Pinger
	failed  map[string]error
	tried   map[string]time.Time
}

// OpenPingers opens the sockets of both families. The error says that neither opened, and both are tried again
// with their next requests; the pingers are there either way.
func OpenPingers(kind Kind, report func(fam Family, p *Pinger, err error)) (*Pingers, error) {
	ps := &Pingers{
		kind:    kind,
		report:  report,
		sockets: make(map[string]*Pinger),
		failed:  make(map[string]error),
		tried:   make(map[string]time.Time),
	}

	var errs []error
	for _, fam := range []Family{IPv4, IPv6} {
		if _, err := ps.Socket(fam); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", fam.Name, err))
		}
	}
	if len(errs) == 2 {
		return ps, errors.Join(errs...)
	}
	return ps, nil
}

// Socket is the socket of the family, opened now if it is not yet and the last try was over a minute ago.
func (ps *Pingers) Socket(fam Family) (*Pinger, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if p := ps.sockets[fam.Name]; p != nil {
		return p, nil
	}
	if at, ok := ps.tried[fam.Name]; ok && time.Since(at) < retryAfter {
		return nil, ps.failed[fam.Name]
	}

	p, err := Open(ps.kind, fam)
	ps.tried[fam.Name] = time.Now()
	if err != nil {
		if ps.failed[fam.Name] == nil && ps.report != nil {
			ps.report(fam, nil, err)
		}
		ps.failed[fam.Name] = err
		return nil, err
	}

	ps.sockets[fam.Name] = p
	delete(ps.failed, fam.Name)
	if ps.report != nil {
		ps.report(fam, p, nil)
	}
	return p, nil
}

// Ping pings the address over the socket of its family; without one the request did not go out, which is an error.
func (ps *Pingers) Ping(ip net.IP, timeout time.Duration) (time.Duration, bool, error) {
	fam := FamilyOf(ip)
	p, err := ps.Socket(fam)
	if err != nil {
		return 0, false, fmt.Errorf("no %s ICMP socket: %w", fam.Name, err)
	}
	return p.Ping(ip, timeout)
}

// Describe tells what each family pings over, for the log: "IPv4 unprivileged, IPv6 none".
func (ps *Pingers) Describe() string {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	parts := make([]string, 0, 2)
	for _, fam := range []Family{IPv4, IPv6} {
		kind := "none"
		if p := ps.sockets[fam.Name]; p != nil {
			kind = string(p.Kind())
		}
		parts = append(parts, fam.Name+" "+kind)
	}
	return strings.Join(parts, ", ")
}

// Close closes the sockets; the requests waiting then time out.
func (ps *Pingers) Close() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	var errs []error
	for name, p := range ps.sockets {
		if err := p.Close(); err != nil {
			errs = append(errs, err)
		}
		delete(ps.sockets, name)
	}
	return errors.Join(errs...)
}
