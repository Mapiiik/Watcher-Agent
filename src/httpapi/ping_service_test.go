package httpapi

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The ping itself needs a raw socket (CAP_NET_RAW), so only the answers before it and a series on a fake engine are
// tested here.

func TestHandlePingBadRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	NewPingService().HandlePing(rec, httptest.NewRequest("POST", "/api/ping", jsonBody("host=192.0.2.1")))

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "bad_request" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePingUnresolvableHost(t *testing.T) {
	rec := httptest.NewRecorder()
	NewPingService().HandlePing(rec, httptest.NewRequest("POST", "/api/ping", jsonBody(`{"host":"cpe.invalid"}`)))

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "host_resolution_failed" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePingOverTheLimit(t *testing.T) {
	for name, body := range map[string]string{
		"too many":  `{"host":"cpe.invalid","count":241,"timeout_ms":500}`,
		"too long":  `{"host":"cpe.invalid","count":1,"timeout_ms":120001}`,
		"overflown": `{"host":"cpe.invalid","count":4294967296,"timeout_ms":4294967296}`,
	} {
		rec := httptest.NewRecorder()
		NewPingService().HandlePing(rec, httptest.NewRequest("POST", "/api/ping", jsonBody(body)))

		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "bad_request" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// The longest ping allowed gets as far as the host.
func TestHandlePingUpToTheLimit(t *testing.T) {
	rec := httptest.NewRecorder()
	NewPingService().HandlePing(rec, httptest.NewRequest("POST", "/api/ping", jsonBody(
		`{"host":"cpe.invalid","count":240,"timeout_ms":500}`,
	)))

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "host_resolution_failed" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

// fakeEngine answers each ping in turn: a time, nothing, or an error.
type fakeEngine []any

func (f *fakeEngine) Ping(net.IP, int, time.Duration) (time.Duration, bool, error) {
	next := (*f)[0]
	*f = (*f)[1:]

	switch answer := next.(type) {
	case time.Duration:
		return answer, true, nil
	case error:
		return 0, false, answer
	}
	return 0, false, nil
}

func TestPingSeriesCountsLostPackets(t *testing.T) {
	engine := fakeEngine{10 * time.Millisecond, nil, 30 * time.Millisecond, nil}

	reply, err := pingSeries(&engine, net.IPv4(192, 0, 2, 1), 4, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if !reply.Reachable || reply.TargetIP != "192.0.2.1" || reply.Sent != 4 || reply.Received != 2 || reply.Lost != 2 ||
		reply.LossPct != 50 || reply.RTTMinMs != 10 || reply.RTTAvgMs != 20 || reply.RTTMaxMs != 30 {
		t.Errorf("%+v", reply)
	}
}

// A request that did not go out says nothing about the host.
func TestPingSeriesLeavesOutWhatWasNotSent(t *testing.T) {
	engine := fakeEngine{10 * time.Millisecond, errors.New("no buffer space"), 30 * time.Millisecond}

	reply, err := pingSeries(&engine, net.IPv4(192, 0, 2, 1), 3, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if reply.Sent != 2 || reply.Received != 2 || reply.Lost != 0 || reply.LossPct != 0 {
		t.Errorf("%+v", reply)
	}
}

func TestPingSeriesWithNothingSentIsAnError(t *testing.T) {
	cause := errors.New("network is unreachable")
	engine := fakeEngine{cause, cause}

	if reply, err := pingSeries(&engine, net.IPv4(192, 0, 2, 1), 2, time.Second); !errors.Is(err, cause) {
		t.Errorf("%+v, %v", reply, err)
	}
}

func TestPingSeriesOfASilentHostIsNoError(t *testing.T) {
	engine := fakeEngine{nil, nil}

	reply, err := pingSeries(&engine, net.IPv4(192, 0, 2, 1), 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if reply.Reachable || reply.Sent != 2 || reply.Lost != 2 || reply.LossPct != 100 {
		t.Errorf("%+v", reply)
	}
}
