package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"watcher-agent/src/httphelpers"
)

type PingService struct {
	// zatím prázdné – ale připravené na budoucí config
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

func NewPingService() *PingService {
	return &PingService{}
}

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

	if req.Count <= 0 {
		req.Count = 3
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 800
	}

	ip := net.ParseIP(req.Host)
	if ip == nil {
		ips, err := net.LookupIP(req.Host)
		if err != nil || len(ips) == 0 {
			httphelpers.WriteError(
				w,
				http.StatusBadRequest,
				"dns_failed",
				"The host could not be resolved.",
			)
			return
		}
		ip = ips[0]
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		httphelpers.WriteError(
			w,
			http.StatusInternalServerError,
			"icmp_unavailable",
			"ICMP listen failed (need CAP_NET_RAW or root).",
		)
		return
	}
	defer c.Close()

	var sent, recv int
	var sum time.Duration
	var minRTT, maxRTT time.Duration

	echoID := int(time.Now().UnixNano() & 0xffff)

	for i := 0; i < req.Count; i++ {
		sent++

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   echoID,
				Seq:  i,
				Data: []byte("watcher"),
			},
		}

		b, _ := msg.Marshal(nil)

		start := time.Now()
		_ = c.SetDeadline(time.Now().Add(time.Duration(req.TimeoutMs) * time.Millisecond))

		if _, err := c.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
			continue
		}

		buf := make([]byte, 1500)
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			continue
		}

		rm, err := icmp.ParseMessage(1, buf[:n])
		if err == nil && rm.Type == ipv4.ICMPTypeEchoReply {
			recv++

			rtt := time.Since(start)

			if recv == 1 || rtt < minRTT {
				minRTT = rtt
			}
			if rtt > maxRTT {
				maxRTT = rtt
			}

			sum += rtt
		}
	}

	lost := sent - recv
	loss := float64(lost) / float64(sent) * 100.0
	avg := 0.0
	min := 0.0
	max := 0.0
	if recv > 0 {
		avg = float64(sum) / float64(recv) / float64(time.Millisecond)
		min = float64(minRTT) / float64(time.Millisecond)
		max = float64(maxRTT) / float64(time.Millisecond)
	}

	httphelpers.WriteJSON(w, PingReply{
		Reachable: recv > 0,
		TargetIP:  ip.String(),
		Sent:      sent,
		Received:  recv,
		Lost:      lost,
		LossPct:   loss,
		RTTMinMs:  min,
		RTTAvgMs:  avg,
		RTTMaxMs:  max,
	})
}
