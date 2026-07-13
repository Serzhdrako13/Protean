// Package pki provides a tiny X.509 certificate authority for the
// certificate-based VPN providers (OpenVPN, IKEv2). It deliberately does the
// CA work in Go rather than shelling out to easy-rsa: no PKI state is
// scattered on the host, and the CA private key lives only where the caller
// chooses to persist it (encrypted, in the panel's database).
//
// The same issuing code backs both supported CA sources:
//   - an internally generated CA (NewInternalCA), and
//   - an externally supplied CA cert+key (LoadCA), e.g. an intermediate
//     exported from step-ca.
//
// A future step-ca-over-ACME implementation can satisfy the same
// CertAuthority interface without holding a CA key at all.
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ClientCreds is an issued leaf certificate and its private key, PEM-encoded.
type ClientCreds struct {
	CertPEM string
	KeyPEM  string
}

// CertAuthority issues server and client certificates and exposes its CA
// certificate for embedding in client bundles.
type CertAuthority interface {
	CACertPEM() string
	IssueServer(cn string, dnsNames []string, ips []net.IP, validFor time.Duration) (certPEM, keyPEM string, err error)
	IssueClient(cn string, validFor time.Duration) (ClientCreds, error)
}

const (
	rsaBits      = 2048
	caCommonName = "Protean CA"
)

// CA is an in-memory certificate authority. Persist its PEM material via
// CACertPEM/CAKeyPEM and reload with LoadCA.
type CA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certDER []byte
	// now is injectable for deterministic tests.
	now func() time.Time
}

// NewInternalCA generates a fresh self-signed CA valid for validFor.
func NewInternalCA(validFor time.Duration) (*CA, error) {
	return newCA(validFor, time.Now)
}

func newCA(validFor time.Duration, now func() time.Time) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCommonName},
		NotBefore:             t.Add(-time.Hour),
		NotAfter:              t.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certDER: der, now: now}, nil
}

// LoadCA reconstructs a CA from previously stored PEM material (either
// NewInternalCA output, or an external/BYOC CA + key).
func LoadCA(caCertPEM, caKeyPEM string) (*CA, error) {
	cert, der, err := parseCertPEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	key, err := parseRSAKeyPEM(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("supplied certificate is not a CA")
	}
	return &CA{cert: cert, key: key, certDER: der, now: time.Now}, nil
}

func (c *CA) CACertPEM() string { return string(encodeCert(c.certDER)) }

// CAKeyPEM returns the CA private key PEM. Callers must store this encrypted.
func (c *CA) CAKeyPEM() string { return string(encodeRSAKey(c.key)) }

func (c *CA) IssueServer(cn string, dnsNames []string, ips []net.IP, validFor time.Duration) (string, string, error) {
	creds, err := c.issue(cn, validFor, x509.ExtKeyUsageServerAuth, dnsNames, ips)
	if err != nil {
		return "", "", err
	}
	return creds.CertPEM, creds.KeyPEM, nil
}

func (c *CA) IssueClient(cn string, validFor time.Duration) (ClientCreds, error) {
	return c.issue(cn, validFor, x509.ExtKeyUsageClientAuth, nil, nil)
}

// SignCSRWithCN signs a client Certificate Signing Request, issuing a leaf
// certificate for the CSR's public key with the given common name and client
// EKU. The CSR's own subject is ignored except that its self-signature is
// verified -- proving the requester holds the matching private key, which
// never reaches the server (CSR-based enrollment). Used for cert providers.
func (c *CA) SignCSRWithCN(csrPEM, cn string, validFor time.Duration) (string, error) {
	if cn == "" {
		return "", fmt.Errorf("common name must not be empty")
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("no CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return "", err
	}
	t := c.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    t.Add(-time.Hour),
		NotAfter:     t.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return "", fmt.Errorf("sign CSR: %w", err)
	}
	return string(encodeCert(der)), nil
}

// RevokedCert is one entry in a certificate revocation list.
type RevokedCert struct {
	Serial    *big.Int
	RevokedAt time.Time
}

// CreateCRL produces a PEM-encoded CRL signed by this CA over the given
// revoked entries. number is a monotonically increasing CRL sequence number.
func (c *CA) CreateCRL(revoked []RevokedCert, number int64, thisUpdate, nextUpdate time.Time) (string, error) {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		if r.Serial == nil {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   r.Serial,
			RevocationTime: r.RevokedAt,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return "", fmt.Errorf("create CRL: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}

// SerialFromCertPEM extracts the certificate serial number from a PEM cert,
// used to record a revocation for a stored client cert.
func SerialFromCertPEM(certPEM string) (*big.Int, error) {
	cert, _, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	return cert.SerialNumber, nil
}

func (c *CA) issue(cn string, validFor time.Duration, eku x509.ExtKeyUsage, dnsNames []string, ips []net.IP) (ClientCreds, error) {
	if cn == "" {
		return ClientCreds{}, fmt.Errorf("common name must not be empty")
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return ClientCreds{}, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return ClientCreds{}, err
	}
	t := c.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    t.Add(-time.Hour),
		NotAfter:     t.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return ClientCreds{}, fmt.Errorf("sign leaf: %w", err)
	}
	return ClientCreds{
		CertPEM: string(encodeCert(der)),
		KeyPEM:  string(encodeRSAKey(key)),
	}, nil
}

func randomSerial() (*big.Int, error) {
	// 128-bit random serial.
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return n, nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeRSAKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(key)})
}

func mustPKCS8(key *rsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		// RSA keys always marshal; a failure is a programming error.
		panic(err)
	}
	return b
}

func parseCertPEM(s string) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, block.Bytes, nil
}

func parseRSAKeyPEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA key")
		}
		return rk, nil
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key PEM type %q", block.Type)
	}
}
