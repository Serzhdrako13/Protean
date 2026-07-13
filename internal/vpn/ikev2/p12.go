package ikev2

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// BuildP12 packages a client cert + key + CA into a PKCS#12 (.p12) bundle,
// importable on iOS/macOS/Windows/Android/NetworkManager. Encrypted with
// password.
func BuildP12(clientCertPEM, clientKeyPEM, caCertPEM, password string) ([]byte, error) {
	cert, err := parseCert(clientCertPEM)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	key, err := parseKey(clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("client key: %w", err)
	}
	ca, err := parseCert(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}
	return pkcs12.Modern.Encode(key, cert, []*x509.Certificate{ca}, password)
}

func parseCert(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKey(s string) (any, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
