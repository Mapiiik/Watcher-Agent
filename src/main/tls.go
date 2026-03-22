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

		// Accept both IP and DNS
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
