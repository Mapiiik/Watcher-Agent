package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// TLS 1.2 suites with ECDHE and authenticated encryption only; TLS 1.3 suites are all of that kind.
var tls12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func buildHTTPServer(cfg AppConfig, handler http.Handler) (*http.Server, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:      cfg.ListenHttps,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}, nil
}

// buildTLSConfig uses ACME when AGENT_HOSTNAME is set, otherwise a self-signed certificate made at every start.
func buildTLSConfig(cfg AppConfig) (*tls.Config, error) {
	if cfg.Hostname == "" {
		log.Println("TLS: using self-signed certificate")
		return buildSelfSignedTLS()
	}

	log.Printf("TLS: using ACME for hostname %s", cfg.Hostname)
	return buildACMETLS(cfg)
}

func buildSelfSignedTLS() (*tls.Config, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: tls12CipherSuites,
	}, nil
}

func buildACMETLS(cfg AppConfig) (*tls.Config, error) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Hostname),
		Cache:      autocert.DirCache(cfg.CertDir),
	}

	tlsCfg := m.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.CipherSuites = tls12CipherSuites

	return tlsCfg, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Certificate template
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "watcher-agent",
			Organization: []string{"Watcher"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(30 * 24 * time.Hour), // 30 days

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		// Valid for 127.0.0.1 and localhost
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
		DNSNames: []string{
			"localhost",
		},
	}

	// Self-sign
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode cert and key
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return tls.X509KeyPair(certPEM, keyPEM)
}
