package radius

import (
	"context"
	"fmt"
	"net"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	codeDisconnectRequest radius.Code = 40
	codeDisconnectACK     radius.Code = 41
	codeDisconnectNAK     radius.Code = 42
)

// RFC 5176 Error-Cause attribute
var attrErrorCause = radius.Type(101)

type RadiusDisconnectInput struct {
	NASIP         string `json:"nas_ip"`
	Port          int    `json:"port"`
	Secret        string `json:"secret"`
	UserName      string `json:"username"`
	AcctSessionID string `json:"acct_session_id"`
	FramedIP      string `json:"framed_ip"`
	TimeoutMs     int    `json:"timeout_ms"`
}

type RadiusDisconnectOutput struct {
	Success     bool   `json:"success"`
	Result      string `json:"result"`
	ErrorCauses []int  `json:"error_causes,omitempty"`
}

func Disconnect(cfg Config, in RadiusDisconnectInput) (RadiusDisconnectOutput, error) {
	port := int(cfg.Port)
	if in.Port > 0 {
		port = in.Port
	}

	timeout := cfg.Timeout
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}

	addr := fmt.Sprintf("%s:%d", in.NASIP, port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return RadiusDisconnectOutput{Success: false, Result: "Exception"}, err
	}

	pkt := radius.New(codeDisconnectRequest, []byte(in.Secret))

	if in.UserName != "" {
		rfc2865.UserName_SetString(pkt, in.UserName)
	}
	if in.AcctSessionID != "" {
		pkt.Add(radius.Type(44), radius.Attribute(in.AcctSessionID))
	}
	if in.FramedIP != "" {
		if ip := net.ParseIP(in.FramedIP); ip != nil {
			rfc2865.FramedIPAddress_Set(pkt, ip)
		}
	}
	if in.NASIP != "" {
		if ip := net.ParseIP(in.NASIP); ip != nil {
			rfc2865.NASIPAddress_Set(pkt, ip)
		}
	}

	var lastErr error

	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			timeout,
		)

		resp, err := radius.Exchange(ctx, pkt, udpAddr.String())
		cancel()

		if err != nil {
			lastErr = err

			// sleep only if we will retry again
			if attempt < cfg.Retries {
				time.Sleep(1000 * time.Millisecond)
			}

			continue
		}

		out := RadiusDisconnectOutput{
			Success: false,
			Result:  fmt.Sprintf("Code-%d", resp.Code),
		}

		switch resp.Code {
		case codeDisconnectACK:
			out.Success = true
			out.Result = "Disconnect-ACK"
		case codeDisconnectNAK:
			out.Result = "Disconnect-NAK"
		default:
			out.Result = fmt.Sprintf("Unsupported reply (code %d)", resp.Code)
		}

		// Extract all Error-Cause attributes (RFC 5176)
		vals := resp.Attributes.Get(attrErrorCause)
		if len(vals) == 4 {
			code := int(vals[0])<<24 |
				int(vals[1])<<16 |
				int(vals[2])<<8 |
				int(vals[3])
			out.ErrorCauses = append(out.ErrorCauses, code)
		}

		return out, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("radius disconnect failed without response")
	}

	return RadiusDisconnectOutput{
		Success: false,
		Result:  "Exception",
	}, lastErr
}
