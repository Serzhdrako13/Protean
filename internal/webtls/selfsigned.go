// Package webtls manages the panel's OWN web-listener TLS certificate --
// separate from internal/vpn/pki, which is scoped to VPN client
// certificates (OpenVPN/IKEv2). Four acquisition modes (see
// store.TLSState.Mode): self_signed (this file's CA, the permanent
// fallback in every mode), acme (generic ACME client, any directory URL),
// manual (admin-pasted PEM), proxy (panel doesn't terminate TLS at all).
package webtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// KeyAlgo is an admin-selectable private key algorithm for the self-signed
// leaf cert -- from the simplest/fastest (RSA-2048) to the strictest
// (ECDSA P-384), stored verbatim in store.TLSState.SSKeyAlgo.
type KeyAlgo string

const (
	RSA2048   KeyAlgo = "rsa_2048"
	RSA4096   KeyAlgo = "rsa_4096"
	ECDSAP256 KeyAlgo = "ecdsa_p256"
	ECDSAP384 KeyAlgo = "ecdsa_p384"
)

func generateKey(algo KeyAlgo) (crypto.Signer, error) {
	switch algo {
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "", ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unknown key algorithm %q", algo)
	}
}

func keyToPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func keyFromPEM(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM key block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T is not usable for TLS", key)
	}
	return signer, nil
}

func certFromPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM certificate block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certToPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// GenerateCA creates a new self-signed root CA for issuing the panel's own
// web TLS leaf certs. Generated ONCE ever (see store.SaveTLSSelfSignedCA --
// callers check store.GetTLSSelfSigned's found=false first): its entire
// purpose is to be a stable, always-available fallback identity, so it
// intentionally does NOT rotate just because an admin switches modes back
// and forth or changes the leaf's key algorithm.
func GenerateCA() (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Protean internal web TLS CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return "", "", err
	}
	kp, err := keyToPEM(key)
	if err != nil {
		return "", "", err
	}
	return certToPEM(der), kp, nil
}

// defaultSANs is what a fresh leaf gets before an admin has configured any
// real hostname/IP -- enough for the panel to be reachable over HTTPS
// immediately (browsers will still flag it untrusted, expected for
// self-signed, but the connection is encrypted from the very first boot).
var defaultSANs = []string{"localhost", "127.0.0.1", "::1"}

// splitSANs parses a comma-separated SAN list, falling back to
// defaultSANs when empty.
func splitSANs(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return defaultSANs
	}
	var out []string
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return defaultSANs
	}
	return out
}

// IssueLeaf issues a new leaf certificate signed by the given CA, covering
// the given SANs (hostnames/IPs), with the requested key algorithm and
// validity.
func IssueLeaf(caCertPEM, caKeyPEM string, algo KeyAlgo, sansCSV string, validFor time.Duration) (certPEM, keyPEM string, expires time.Time, err error) {
	caCert, err := certFromPEM(caCertPEM)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("parse CA cert: %w", err)
	}
	caKey, err := keyFromPEM(caKeyPEM)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("parse CA key: %w", err)
	}
	leafKey, err := generateKey(algo)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", time.Time{}, err
	}

	sans := splitSANs(sansCSV)
	notAfter := time.Now().Add(validFor)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sans[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range sans {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("create leaf cert: %w", err)
	}
	kp, err := keyToPEM(leafKey)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return certToPEM(der), kp, notAfter, nil
}
