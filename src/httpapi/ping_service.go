package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"watcher-agent/src/httphelpers"
	"watcher-agent/src/infra/icmpengine"
)

type PingService struct {
	// prepared for future configuration options if needed
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

	engine := icmpengine.Get()
	if err := engine.Acquire(); err != nil {
		httphelpers.WriteError(
			w,
			http.StatusInternalServerError,
			"icmp_unavailable",
			"ICMP engine unavailable.",
		)
		return
	}
	defer engine.Release()

	var sent, recv int
	var sum time.Duration
	var minRTT, maxRTT time.Duration

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond

	for seq := 0; seq < req.Count; seq++ {
		sent++

		rtt, ok, err := engine.Ping(ip, seq, timeout)
		if err != nil || !ok {
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

	lost := sent - recv
	lossPct := float64(lost) / float64(sent) * 100.0

	var avg, min, max float64
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
		LossPct:   lossPct,
		RTTMinMs:  min,
		RTTAvgMs:  avg,
		RTTMaxMs:  max,
	})
}
