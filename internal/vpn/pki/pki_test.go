package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func parseLeaf(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("no PEM block in cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

func verifyChain(t *testing.T, ca *CA, leafPEM string, usage x509.ExtKeyUsage) {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ca.CACertPEM())) {
		t.Fatal("failed to add CA to pool")
	}
	leaf := parseLeaf(t, leafPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{usage},
	}); err != nil {
		t.Errorf("chain verify failed: %v", err)
	}
}

func TestInternalCAIssuesVerifiableCerts(t *testing.T) {
	ca, err := NewInternalCA(10 * 365 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("NewInternalCA: %v", err)
	}

	// Client cert chains to CA and is valid for client auth.
	cc, err := ca.IssueClient("office-a", 2*365*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	verifyChain(t, ca, cc.CertPEM, x509.ExtKeyUsageClientAuth)
	if parseLeaf(t, cc.CertPEM).Subject.CommonName != "office-a" {
		t.Error("client CN mismatch")
	}

	// Server cert with SANs, valid for server auth.
	sc, _, err := ca.IssueServer("vpn.example.com", []string{"vpn.example.com"}, []net.IP{net.ParseIP("203.0.113.10")}, 2*365*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	verifyChain(t, ca, sc, x509.ExtKeyUsageServerAuth)
	leaf := parseLeaf(t, sc)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "vpn.example.com" {
		t.Errorf("server SAN dns = %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 {
		t.Errorf("server SAN ip = %v", leaf.IPAddresses)
	}
}

func TestCARoundTripReload(t *testing.T) {
	ca, err := NewInternalCA(10 * 365 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("NewInternalCA: %v", err)
	}
	certPEM, keyPEM := ca.CACertPEM(), ca.CAKeyPEM()

	// Reload as an "external/BYOC" CA and issue -- proves persistence works
	// and the external path uses the same issuing code.
	reloaded, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	cc, err := reloaded.IssueClient("client-b", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient after reload: %v", err)
	}
	verifyChain(t, ca, cc.CertPEM, x509.ExtKeyUsageClientAuth) // verifies against original CA pool
}

func TestLoadCARejectsNonCA(t *testing.T) {
	ca, _ := NewInternalCA(time.Hour)
	// A leaf cert is not a CA.
	cc, _ := ca.IssueClient("x", time.Hour)
	if _, err := LoadCA(cc.CertPEM, cc.KeyPEM); err == nil {
		t.Error("LoadCA should reject a non-CA certificate")
	}
}

func TestIssueEmptyCN(t *testing.T) {
	ca, _ := NewInternalCA(time.Hour)
	if _, err := ca.IssueClient("", time.Hour); err == nil {
		t.Error("expected error for empty CN")
	}
}
