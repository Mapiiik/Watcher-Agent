package routerosapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// CA signs router certificates the way provisioning will.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func NewCA(t testing.TB) *CA {
	t.Helper()

	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return &CA{cert: cert, key: key}
}

// Fingerprint is the SHA-256 of the CA certificate.
func (ca *CA) Fingerprint() []byte {
	sum := sha256.Sum256(ca.cert.Raw)
	return sum[:]
}

// Leaf is a router certificate valid until notAfter, sent with the CA behind it like a device holding both.
func (ca *CA) Leaf(t testing.TB, notAfter time.Time) tls.Certificate {
	t.Helper()

	key := newKey(t)
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate(notAfter), ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

// SelfSigned is a certificate a router makes for itself.
func SelfSigned(t testing.TB) tls.Certificate {
	t.Helper()

	key := newKey(t)
	tmpl := leafTemplate(time.Now().Add(24 * time.Hour))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// leafTemplate names no address: routers are renumbered, so the agent does not check one.
func leafTemplate(notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "router"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
