package radius

import (
	"context"
	"errors"
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
	// "resultException" indicates a local or protocol-level failure
	// before a valid RADIUS response was received.
	resultException     string = "Exception"
	resultDisconnectACK string = "Disconnect-ACK"
	resultDisconnectNAK string = "Disconnect-NAK"
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
		return RadiusDisconnectOutput{Success: false, Result: resultException}, err
	}

	pkt := radius.New(codeDisconnectRequest, []byte(in.Secret))

	if in.UserName != "" {
		if err := rfc2865.UserName_SetString(pkt, in.UserName); err != nil {
			return RadiusDisconnectOutput{Success: false, Result: resultException}, err
		}
	}
	if in.AcctSessionID != "" {
		pkt.Add(radius.Type(44), radius.Attribute(in.AcctSessionID))
	}
	if in.FramedIP != "" {
		if ip := net.ParseIP(in.FramedIP); ip != nil {
			if err := rfc2865.FramedIPAddress_Set(pkt, ip); err != nil {
				return RadiusDisconnectOutput{Success: false, Result: resultException}, err
			}
		}
	}
	if in.NASIP != "" {
		if ip := net.ParseIP(in.NASIP); ip != nil {
			if err := rfc2865.NASIPAddress_Set(pkt, ip); err != nil {
				return RadiusDisconnectOutput{Success: false, Result: resultException}, err
			}
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
			out.Result = resultDisconnectACK
		case codeDisconnectNAK:
			out.Result = resultDisconnectNAK
		default:
			out.Result = fmt.Sprintf("Unsupported reply (code %d)", resp.Code)
		}

		// Extract all Error-Cause attributes (RFC 5176)
		vals := resp.Get(attrErrorCause)
		if len(vals) == 4 {
			code := int(vals[0])<<24 |
				int(vals[1])<<16 |
				int(vals[2])<<8 |
				int(vals[3])
			out.ErrorCauses = append(out.ErrorCauses, code)
		}

		return out, nil
	}

	if lastErr != nil {
		if errors.Is(lastErr, context.DeadlineExceeded) {
			return RadiusDisconnectOutput{
				Success: false,
				Result:  fmt.Sprintf("Timeout after %d attempts", cfg.Retries+1),
			}, nil
		}

		return RadiusDisconnectOutput{
			Success: false,
			Result:  resultException,
		}, lastErr
	}

	return RadiusDisconnectOutput{
		Success: false,
		Result:  resultException,
	}, fmt.Errorf("RADIUS disconnect failed without response")
}
