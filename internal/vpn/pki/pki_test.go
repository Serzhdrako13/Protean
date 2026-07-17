package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedECCA hand-builds a self-signed EC CA cert+key, PEM-encoded in
// the given private-key block type -- simulates what a real external CA
// (easy-rsa/step-ca/openssl with an EC curve) would hand over for import,
// which NewInternalCA (always RSA) can't produce itself.
func selfSignedECCA(t *testing.T, keyBlockType string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "External EC CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign EC CA: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	switch keyBlockType {
	case "EC PRIVATE KEY":
		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalECPrivateKey: %v", err)
		}
		keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	case "PRIVATE KEY":
		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
	default:
		t.Fatalf("unhandled key block type %q", keyBlockType)
	}
	return certPEM, keyPEM
}

// TestLoadCAAcceptsECKey covers importing a real-world external EC CA in
// both the legacy SEC1 ("EC PRIVATE KEY", e.g. `openssl ecparam -genkey`)
// and modern PKCS8 ("PRIVATE KEY") formats -- before this, LoadCA only
// accepted RSA and would reject any EC-keyed CA outright.
func TestLoadCAAcceptsECKey(t *testing.T) {
	for _, blockType := range []string{"EC PRIVATE KEY", "PRIVATE KEY"} {
		t.Run(blockType, func(t *testing.T) {
			certPEM, keyPEM := selfSignedECCA(t, blockType)
			ca, err := LoadCA(certPEM, keyPEM)
			if err != nil {
				t.Fatalf("LoadCA with EC key (%s): %v", blockType, err)
			}
			cc, err := ca.IssueClient("ec-client", time.Hour)
			if err != nil {
				t.Fatalf("IssueClient from EC-keyed CA: %v", err)
			}
			verifyChain(t, ca, cc.CertPEM, x509.ExtKeyUsageClientAuth)

			// Round-trip: the CA's own key PEM (re-encoded via CAKeyPEM,
			// always PKCS8) must itself reload and keep working.
			reloaded, err := LoadCA(ca.CACertPEM(), ca.CAKeyPEM())
			if err != nil {
				t.Fatalf("reload EC CA after CAKeyPEM round-trip: %v", err)
			}
			if _, err := reloaded.IssueClient("ec-client-2", time.Hour); err != nil {
				t.Fatalf("IssueClient after EC CA round-trip: %v", err)
			}
		})
	}
}

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

// TestParseCRLRoundTrip covers the CA-import path's CRL side: a CRL this
// same package created (CreateCRL) must parse back to the same revoked
// serials/timestamps and sequence number via ParseCRL, since that's exactly
// what happens when adopting an external server ("its CreateCRL output" is
// what an admin pastes in, functionally).
func TestParseCRLRoundTrip(t *testing.T) {
	ca, err := NewInternalCA(time.Hour)
	if err != nil {
		t.Fatalf("NewInternalCA: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	revoked := []RevokedCert{
		{Serial: big.NewInt(1001), RevokedAt: now},
		{Serial: big.NewInt(1002), RevokedAt: now.Add(-time.Hour)},
	}
	crlPEM, err := ca.CreateCRL(revoked, 7, now.Add(-time.Minute), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}

	got, number, err := ParseCRL(crlPEM)
	if err != nil {
		t.Fatalf("ParseCRL: %v", err)
	}
	if number != 7 {
		t.Errorf("number = %d, want 7", number)
	}
	if len(got) != 2 {
		t.Fatalf("got %d revoked entries, want 2", len(got))
	}
	for i, want := range revoked {
		if got[i].Serial.Cmp(want.Serial) != 0 {
			t.Errorf("entry %d serial = %v, want %v", i, got[i].Serial, want.Serial)
		}
		if !got[i].RevokedAt.Equal(want.RevokedAt) {
			t.Errorf("entry %d revokedAt = %v, want %v", i, got[i].RevokedAt, want.RevokedAt)
		}
	}
}

func TestVerifyClientCert(t *testing.T) {
	ca, err := NewInternalCA(time.Hour)
	if err != nil {
		t.Fatalf("NewInternalCA: %v", err)
	}
	cc, err := ca.IssueClient("adopted", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	cn, err := ca.VerifyClientCert(cc.CertPEM)
	if err != nil {
		t.Fatalf("VerifyClientCert: %v", err)
	}
	if cn != "adopted" {
		t.Errorf("cn = %q, want adopted", cn)
	}

	other, err := NewInternalCA(time.Hour)
	if err != nil {
		t.Fatalf("NewInternalCA: %v", err)
	}
	if _, err := other.VerifyClientCert(cc.CertPEM); err == nil {
		t.Error("VerifyClientCert should reject a cert signed by a different CA")
	}

	// A server cert (ExtKeyUsageServerAuth, not ClientAuth) must also be
	// rejected -- VerifyClientCert is specifically for client credentials.
	serverCertPEM, _, err := ca.IssueServer("vpn.example.com", nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if _, err := ca.VerifyClientCert(serverCertPEM); err == nil {
		t.Error("VerifyClientCert should reject a server certificate")
	}
}

func TestMatchesPrivateKey(t *testing.T) {
	ca, err := NewInternalCA(time.Hour)
	if err != nil {
		t.Fatalf("NewInternalCA: %v", err)
	}
	a, err := ca.IssueClient("a", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient a: %v", err)
	}
	b, err := ca.IssueClient("b", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient b: %v", err)
	}
	if err := MatchesPrivateKey(a.CertPEM, a.KeyPEM); err != nil {
		t.Errorf("expected matching cert/key to pass: %v", err)
	}
	if err := MatchesPrivateKey(a.CertPEM, b.KeyPEM); err == nil {
		t.Error("expected mismatched cert/key to be rejected")
	}
}

func TestParseCRLRejectsGarbage(t *testing.T) {
	if _, _, err := ParseCRL("not a pem block"); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, _, err := ParseCRL("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"); err == nil {
		t.Error("expected error for a CERTIFICATE block, not X509 CRL")
	}
}
