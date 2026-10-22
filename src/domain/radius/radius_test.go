package radius

import (
	"encoding/binary"
	"net"
	"slices"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const secret = "test-secret"

// nas answers every Disconnect-Request with the given code and Error-Cause values and keeps the last request.
type nas struct {
	port     int
	requests chan *radius.Packet
}

func startNAS(t *testing.T, code radius.Code, errorCauses ...uint32) *nas {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	n := &nas{port: conn.LocalAddr().(*net.UDPAddr).Port, requests: make(chan *radius.Packet, 4)}
	server := &radius.PacketServer{
		SecretSource: radius.StaticSecretSource([]byte(secret)),
		Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
			n.requests <- r.Packet
			resp := r.Response(code)
			for _, c := range errorCauses {
				resp.Add(attrErrorCause, binary.BigEndian.AppendUint32(nil, c))
			}
			_ = w.Write(resp)
		}),
	}

	go func() { _ = server.Serve(conn) }()
	t.Cleanup(func() { _ = conn.Close() })

	return n
}

func input(port int) RadiusDisconnectInput {
	return RadiusDisconnectInput{
		NASIP:         "127.0.0.1",
		Port:          port,
		Secret:        secret,
		UserName:      "customer@netair",
		AcctSessionID: "81a00012",
		FramedIP:      "100.64.1.2",
	}
}

var config = Config{Port: 3799, Timeout: time.Second, Retries: 0}

func TestDisconnectACK(t *testing.T) {
	n := startNAS(t, codeDisconnectACK)

	out, err := Disconnect(config, input(n.port))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Success || out.Result != resultDisconnectACK || out.ErrorCauses != nil {
		t.Errorf("out = %+v, want a plain Disconnect-ACK", out)
	}

	req := <-n.requests
	if req.Code != codeDisconnectRequest {
		t.Errorf("request code = %d, want %d", req.Code, codeDisconnectRequest)
	}
	if got := rfc2865.UserName_GetString(req); got != "customer@netair" {
		t.Errorf("User-Name = %q", got)
	}
	if got := string(req.Get(44)); got != "81a00012" {
		t.Errorf("Acct-Session-Id = %q", got)
	}
	if got := rfc2865.FramedIPAddress_Get(req); !got.Equal(net.ParseIP("100.64.1.2")) {
		t.Errorf("Framed-IP-Address = %v", got)
	}
	if got := rfc2865.NASIPAddress_Get(req); !got.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("NAS-IP-Address = %v", got)
	}
}

func TestDisconnectSendsOnlyWhatIsGiven(t *testing.T) {
	n := startNAS(t, codeDisconnectACK)

	in := input(n.port)
	in.UserName, in.AcctSessionID, in.FramedIP = "", "", "not-an-ip"
	if _, err := Disconnect(config, in); err != nil {
		t.Fatal(err)
	}

	req := <-n.requests
	for _, typ := range []radius.Type{rfc2865.UserName_Type, 44, rfc2865.FramedIPAddress_Type} {
		if _, ok := req.Lookup(typ); ok {
			t.Errorf("attribute %d sent although not given", typ)
		}
	}
}

func TestDisconnectNAKWithErrorCauses(t *testing.T) {
	n := startNAS(t, codeDisconnectNAK, 503, 504)

	out, err := Disconnect(config, input(n.port))
	if err != nil {
		t.Fatal(err)
	}
	if out.Success || out.Result != resultDisconnectNAK || !slices.Equal(out.ErrorCauses, []int{503, 504}) {
		t.Errorf("out = %+v, want Disconnect-NAK with causes 503 and 504", out)
	}
}

func TestDisconnectUnsupportedReply(t *testing.T) {
	n := startNAS(t, radius.CodeCoAACK)

	out, err := Disconnect(config, input(n.port))
	if err != nil {
		t.Fatal(err)
	}
	if out.Success || out.Result != "Unsupported reply (code 44)" {
		t.Errorf("out = %+v", out)
	}
}

func TestDisconnectPortFromConfig(t *testing.T) {
	n := startNAS(t, codeDisconnectACK)

	cfg := config
	cfg.Port = uint16(n.port) //nolint:gosec // a UDP port fits
	in := input(0)

	if out, err := Disconnect(cfg, in); err != nil || !out.Success {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
}

func TestDisconnectTimeout(t *testing.T) {
	// A NAS that never answers
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	in := input(conn.LocalAddr().(*net.UDPAddr).Port)
	in.TimeoutMs = 100

	start := time.Now()
	out, err := Disconnect(config, in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Success || out.Result != "Timeout after 1 attempts" {
		t.Errorf("out = %+v", out)
	}
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Errorf("took %v, timeout_ms 100 was not used", elapsed)
	}
}

func TestDisconnectUnresolvableNAS(t *testing.T) {
	in := input(3799)
	in.NASIP = "nas.invalid"

	out, err := Disconnect(config, in)
	if err == nil || out.Success || out.Result != resultException {
		t.Errorf("out = %+v, err = %v", out, err)
	}
}
