package routeros

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/go-routeros/routeros/v3"
)

const (
	TransportTLS   = "api-ssl"
	TransportPlain = "api"
)

var (
	ErrUnreachable        = errors.New("no connection to the router")
	ErrLoginFailed        = errors.New("the router refused the login")
	ErrCertificateInvalid = errors.New("the router's certificate is not signed by the configured CA")
	ErrCommandFailed      = errors.New("the router refused a command")
)

// Session is one logged-in connection to a device.
type Session struct {
	// How the session talks to the device, api-ssl or api
	Transport string

	conn    net.Conn
	client  *routeros.Client
	timeout time.Duration
}

// Open connects to the device and logs in.
func Open(cfg Config, host string) (*Session, error) {
	conn, transport, err := dial(cfg, host)
	if err != nil {
		return nil, err
	}

	client, err := routeros.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}

	s := &Session{Transport: transport, conn: conn, client: client, timeout: cfg.Timeout}

	s.extend()
	if err := client.Login(cfg.Username, cfg.Password); err != nil {
		_ = s.Close()

		var deviceErr *routeros.DeviceError
		if errors.As(err, &deviceErr) {
			return nil, fmt.Errorf("%w: %s", ErrLoginFailed, message(deviceErr))
		}
		return nil, fmt.Errorf("%w: login over %s: %v", ErrUnreachable, transport, err)
	}

	return s, nil
}

// Run sends one command and returns the attributes of every item it answered with.
func (s *Session) Run(words ...string) ([]map[string]string, error) {
	s.extend()

	reply, err := s.client.Run(words...)
	if err != nil {
		var deviceErr *routeros.DeviceError
		if errors.As(err, &deviceErr) {
			return nil, fmt.Errorf("%w: %s: %s", ErrCommandFailed, words[0], message(deviceErr))
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrUnreachable, words[0], err)
	}

	rows := make([]map[string]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		rows = append(rows, re.Map)
	}

	return rows, nil
}

func (s *Session) Close() error {
	return s.client.Close()
}

// extend gives the next exchange its own timeout. The library ignores contexts outside its async mode, so the
// deadline sits on the connection.
func (s *Session) extend() {
	_ = s.conn.SetDeadline(time.Now().Add(s.timeout))
}

// dial opens api-ssl, or the plain api where the router cannot do TLS at all and the configuration allows it.
func dial(cfg Config, host string) (net.Conn, string, error) {
	conn, err := dialTLS(cfg, host)
	if err == nil {
		return conn, TransportTLS, nil
	}
	if errors.Is(err, ErrCertificateInvalid) {
		return nil, "", err
	}

	reason := plainReason(err)
	if reason == "" || !cfg.PlainFallback {
		return nil, "", fmt.Errorf("%w: api-ssl: %v", ErrUnreachable, err)
	}

	conn, plainErr := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(cfg.PlainPort)), cfg.Timeout)
	if plainErr != nil {
		return nil, "", fmt.Errorf("%w: api-ssl: %v; api: %v", ErrUnreachable, err, plainErr)
	}

	// Every unencrypted connection is written down, the log then shows which routers still lack a certificate
	log.Printf("RouterOS API %s: plain api (%s)", host, reason)

	return conn, TransportPlain, nil
}

func dialTLS(cfg Config, host string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	d := tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Routers are reached by addresses that change, so no name is checked. Whether the certificate is checked
		// at all depends on the CA fingerprint, see verifyConnection.
		InsecureSkipVerify: true, //nolint:gosec
		VerifyConnection:   verifyConnection(cfg.CAFingerprint),
	}}

	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(cfg.TLSPort)))
}

// verifyConnection accepts any certificate without a CA fingerprint. With one, the CA has to be in the chain the
// router sends and has to have signed its certificate; who signed it is the identity, not the device or its address.
func verifyConnection(caFingerprint []byte) func(tls.ConnectionState) error {
	if caFingerprint == nil {
		return nil
	}

	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("%w: the router sent no certificate", ErrCertificateInvalid)
		}

		var ca *x509.Certificate
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			if sum := sha256.Sum256(cert.Raw); bytes.Equal(sum[:], caFingerprint) {
				ca = cert
				continue
			}
			intermediates.AddCert(cert)
		}
		if ca == nil || !ca.IsCA {
			return fmt.Errorf("%w: the CA is not in the chain the router sent", ErrCertificateInvalid)
		}

		roots := x509.NewCertPool()
		roots.AddCert(ca)

		if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return fmt.Errorf("%w: %v", ErrCertificateInvalid, err)
		}

		return nil
	}
}

// plainReason says why the plain api may be tried, empty when it may not. Only a router that does no TLS at all
// qualifies: api-ssl refused, or a handshake failure, which is what RouterOS answers without a certificate since it
// then offers anonymous DH only. A timeout or a broken handshake may be somebody in between and stays an error.
func plainReason(err error) string {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "api-ssl refused"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" && opErr.Err != nil &&
		opErr.Err.Error() == "tls: handshake failure" {
		return "no certificate for api-ssl"
	}

	return ""
}

// message is what the device said, without the library's prefix.
func message(err *routeros.DeviceError) string {
	if m := err.Sentence.Map["message"]; m != "" {
		return m
	}
	return err.Error()
}
