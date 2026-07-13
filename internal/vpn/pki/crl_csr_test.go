package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeCSR generates a client keypair and a PEM CSR for the given CN. The
// private key never leaves the caller -- mirroring CSR-based enrollment.
func makeCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestSignCSRWithCN(t *testing.T) {
	ca, _ := NewInternalCA(10 * 365 * 24 * time.Hour)
	csr := makeCSR(t, "csr-requested-name")

	certPEM, err := ca.SignCSRWithCN(csr, "office-csr", 2*365*24*time.Hour)
	if err != nil {
		t.Fatalf("SignCSRWithCN: %v", err)
	}
	// Chains to CA, valid for client auth, and CN is the panel-chosen name
	// (not the CSR's own subject).
	verifyChain(t, ca, certPEM, x509.ExtKeyUsageClientAuth)
	if cn := parseLeaf(t, certPEM).Subject.CommonName; cn != "office-csr" {
		t.Errorf("CN = %q, want office-csr", cn)
	}
}

func TestSignCSRRejectsBadInput(t *testing.T) {
	ca, _ := NewInternalCA(time.Hour)
	if _, err := ca.SignCSRWithCN("not a pem", "x", time.Hour); err == nil {
		t.Error("expected error for non-PEM CSR")
	}
	if _, err := ca.SignCSRWithCN(makeCSR(t, "x"), "", time.Hour); err == nil {
		t.Error("expected error for empty CN")
	}
	// A tampered CSR body must fail signature verification.
	bad := makeCSR(t, "y")
	block, _ := pem.Decode([]byte(bad))
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	tampered := string(pem.EncodeToMemory(block))
	if _, err := ca.SignCSRWithCN(tampered, "y", time.Hour); err == nil {
		t.Error("expected signature-check failure on tampered CSR")
	}
}

func TestCreateCRLContainsRevokedSerials(t *testing.T) {
	ca, _ := NewInternalCA(10 * 365 * 24 * time.Hour)
	now := time.Now()
	s1, s2 := big.NewInt(111), big.NewInt(222)
	crlPEM, err := ca.CreateCRL([]RevokedCert{
		{Serial: s1, RevokedAt: now},
		{Serial: s2, RevokedAt: now},
	}, 1, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	block, _ := pem.Decode([]byte(crlPEM))
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("bad CRL PEM: %+v", block)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	// Signed by the CA.
	if err := crl.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("CRL not signed by CA: %v", err)
	}
	got := map[string]bool{}
	for _, e := range crl.RevokedCertificateEntries {
		got[e.SerialNumber.String()] = true
	}
	if !got["111"] || !got["222"] {
		t.Errorf("revoked serials = %v, want 111 and 222", got)
	}
}

func TestSerialFromCertPEM(t *testing.T) {
	ca, _ := NewInternalCA(time.Hour)
	cc, _ := ca.IssueClient("serialtest", time.Hour)
	serial, err := SerialFromCertPEM(cc.CertPEM)
	if err != nil {
		t.Fatalf("SerialFromCertPEM: %v", err)
	}
	if serial.Sign() <= 0 {
		t.Errorf("serial should be positive, got %v", serial)
	}
}

func TestEmptyCRLIsValid(t *testing.T) {
	ca, _ := NewInternalCA(time.Hour)
	now := time.Now()
	crlPEM, err := ca.CreateCRL(nil, 1, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateCRL(empty): %v", err)
	}
	block, _ := pem.Decode([]byte(crlPEM))
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("parse empty CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("empty CRL should have no entries, got %d", len(crl.RevokedCertificateEntries))
	}
}
