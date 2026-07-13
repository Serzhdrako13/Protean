package webtls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func mustParseCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("invalid PEM: %s", pemStr)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cert := mustParseCert(t, certPEM)
	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
	if _, err := keyFromPEM(keyPEM); err != nil {
		t.Errorf("CA key doesn't parse back: %v", err)
	}
}

func TestIssueLeafKeyAlgos(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caCert := mustParseCert(t, caCertPEM)

	for _, tc := range []struct {
		algo    KeyAlgo
		checkFn func(t *testing.T, pub any)
	}{
		{RSA2048, func(t *testing.T, pub any) {
			k, ok := pub.(*rsa.PublicKey)
			if !ok || k.N.BitLen() != 2048 {
				t.Errorf("expected RSA-2048 pubkey, got %T", pub)
			}
		}},
		{RSA4096, func(t *testing.T, pub any) {
			k, ok := pub.(*rsa.PublicKey)
			if !ok || k.N.BitLen() != 4096 {
				t.Errorf("expected RSA-4096 pubkey, got %T", pub)
			}
		}},
		{ECDSAP256, func(t *testing.T, pub any) {
			k, ok := pub.(*ecdsa.PublicKey)
			if !ok || k.Curve.Params().BitSize != 256 {
				t.Errorf("expected ECDSA P-256 pubkey, got %T", pub)
			}
		}},
		{ECDSAP384, func(t *testing.T, pub any) {
			k, ok := pub.(*ecdsa.PublicKey)
			if !ok || k.Curve.Params().BitSize != 384 {
				t.Errorf("expected ECDSA P-384 pubkey, got %T", pub)
			}
		}},
	} {
		t.Run(string(tc.algo), func(t *testing.T) {
			leafCertPEM, leafKeyPEM, expires, err := IssueLeaf(caCertPEM, caKeyPEM, tc.algo, "vpn.example.com,203.0.113.10", 90*24*time.Hour)
			if err != nil {
				t.Fatalf("IssueLeaf: %v", err)
			}
			leaf := mustParseCert(t, leafCertPEM)
			tc.checkFn(t, leaf.PublicKey)

			if err := leaf.CheckSignatureFrom(caCert); err != nil {
				t.Errorf("leaf not signed by CA: %v", err)
			}
			if _, err := keyFromPEM(leafKeyPEM); err != nil {
				t.Errorf("leaf key doesn't parse: %v", err)
			}
			if !expires.After(time.Now().Add(89 * 24 * time.Hour)) {
				t.Errorf("expires = %v, want ~90 days out", expires)
			}

			foundDomain, foundIP := false, false
			for _, d := range leaf.DNSNames {
				if d == "vpn.example.com" {
					foundDomain = true
				}
			}
			for _, ip := range leaf.IPAddresses {
				if ip.String() == "203.0.113.10" {
					foundIP = true
				}
			}
			if !foundDomain || !foundIP {
				t.Errorf("SANs = dns:%v ip:%v, missing expected entries", leaf.DNSNames, leaf.IPAddresses)
			}
		})
	}
}

func TestIssueLeafDefaultSANsWhenEmpty(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	leafCertPEM, _, _, err := IssueLeaf(caCertPEM, caKeyPEM, ECDSAP256, "", time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leaf := mustParseCert(t, leafCertPEM)
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "localhost" {
		t.Errorf("expected default SANs to include localhost, got dns:%v ip:%v", leaf.DNSNames, leaf.IPAddresses)
	}
	foundLoopback := false
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Errorf("expected default SANs to include 127.0.0.1, got %v", leaf.IPAddresses)
	}
}
