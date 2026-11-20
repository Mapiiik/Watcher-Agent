package httpapi

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"watcher-agent/src/httphelpers"
	"watcher-agent/src/infra/icmpsocket"
)

// maxPingMs is what a ping may take when nothing answers, under the time the server gives a request.
const maxPingMs = 120_000

// PingService pings over one ICMP socket for each address family, opened at start and kept.
type PingService struct {
	pingers *icmpsocket.Pingers
}

type PingRequest struct {
	Host      string `json:"host"`
	Count     int    `json:"count"`
	TimeoutMs int    `json:"timeout_ms"`
}

type PingReply struct {
	Reachable bool    `json:"reachable"`
	TargetIP  string  `json:"target_ip"`
	Sent      int     `json:"sent"`
	Received  int     `json:"received"`
	Lost      int     `json:"lost"`
	LossPct   float64 `json:"loss_pct"`
	RTTMinMs  float64 `json:"rtt_min_ms"`
	RTTAvgMs  float64 `json:"rtt_avg_ms"`
	RTTMaxMs  float64 `json:"rtt_max_ms"`
}

// echoSender is an ICMP socket, as far as a series of pings needs one.
type echoSender interface {
	Ping(net.IP, time.Duration) (time.Duration, bool, error)
}

// NewPingService opens the sockets of both families right away, so that the log tells at start how the agent
// pings. A socket that cannot be opened is tried again a minute later.
func NewPingService(kind icmpsocket.Kind) *PingService {
	pingers, _ := icmpsocket.OpenPingers(kind, func(fam icmpsocket.Family, p *icmpsocket.Pinger, err error) {
		if err != nil {
			log.Printf("ICMP %s: %v", fam.Name, err)
			return
		}
		log.Printf("ICMP %s: pinging over an %s socket", fam.Name, p.Kind())
	})
	return &PingService{pingers: pingers}
}

// HandlePing pings an address or a name (IPv6 preferred) and reports the loss and round-trip times.
func (s *PingService) HandlePing(w http.ResponseWriter, r *http.Request) {
	var req PingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httphelpers.WriteError(
			w,
			http.StatusBadRequest,
			"bad_request",
			"Invalid JSON request body.",
		)
		return
	}

	// Set defaults if not provided
	if req.Count <= 0 {
		req.Count = 3
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 800
	}

	if req.Count > maxPingMs/req.TimeoutMs {
		httphelpers.WriteError(
			w,
			http.StatusBadRequest,
			"bad_request",
			fmt.Sprintf("'count' times 'timeout_ms' may be %d at most.", maxPingMs),
		)
		return
	}

	// Validate host (must be a valid IP address or resolvable hostname)
	ip := net.ParseIP(req.Host)
	if ip == nil {
		ips, err := net.LookupIP(req.Host)
		if err != nil || len(ips) == 0 {
			httphelpers.WriteError(
				w,
				http.StatusBadRequest,
				"host_resolution_failed",
				"The host could not be resolved.",
			)
			return
		}

		// Prefer IPv6 if available
		for _, candidate := range ips {
			if candidate.To4() == nil {
				ip = candidate
				break
			}
		}

		// Fallback to first IP (likely IPv4)
		if ip == nil {
			ip = ips[0]
		}
	}

	pinger, err := s.pingers.Socket(icmpsocket.FamilyOf(ip))
	if err != nil {
		httphelpers.WriteError(
			w,
			http.StatusInternalServerError,
			"icmp_unavailable",
			fmt.Sprintf("No ICMP socket: %s", err),
		)
		return
	}

	reply, err := pingSeries(pinger, ip, req.Count, time.Duration(req.TimeoutMs)*time.Millisecond)
	if err != nil {
		httphelpers.WriteError(
			w,
			http.StatusInternalServerError,
			"ping_failed",
			fmt.Sprintf("The ping could not be sent: %s", err),
		)
		return
	}

	httphelpers.WriteJSON(w, reply)
}

// pingSeries pings the address count times. A request that did not go out is not a lost packet and says nothing about
// the host, so it counts for nothing, and with none sent there is only the error to tell.
func pingSeries(pinger echoSender, ip net.IP, count int, timeout time.Duration) (PingReply, error) {
	var sent, recv int
	var sum time.Duration
	var minRTT, maxRTT time.Duration
	var sendErr error

	for range count {
		rtt, ok, err := pinger.Ping(ip, timeout)
		if err != nil {
			sendErr = err
			continue
		}

		sent++

		if !ok {
			continue
		}

		recv++

		if recv == 1 || rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}

		sum += rtt
	}

	if sent == 0 {
		return PingReply{}, sendErr
	}

	lost := sent - recv
	lossPct := float64(lost) / float64(sent) * 100.0

	var avg, min, max float64
	if recv > 0 {
		avg = float64(sum) / float64(recv) / float64(time.Millisecond)
		min = float64(minRTT) / float64(time.Millisecond)
		max = float64(maxRTT) / float64(time.Millisecond)
	}

	return PingReply{
		Reachable: recv > 0,
		TargetIP:  ip.String(),
		Sent:      sent,
		Received:  recv,
		Lost:      lost,
		LossPct:   lossPct,
		RTTMinMs:  min,
		RTTAvgMs:  avg,
		RTTMaxMs:  max,
	}, nil
}
