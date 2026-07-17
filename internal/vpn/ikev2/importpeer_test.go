package ikev2

import (
	"context"
	"fmt"
	"testing"
	"time"

	"protean/internal/vpn/pki"
)

type fakeSSH struct{}

func (fakeSSH) Run(context.Context, string) (string, error) { return "", nil }
func (fakeSSH) ReadFile(context.Context, string) (string, error) {
	return "", fmt.Errorf("no such file")
}
func (fakeSSH) WriteFile(context.Context, string, string) error { return nil }

type fakeEnc struct{}

func (fakeEnc) Seal(s string) ([]byte, error) { return []byte(s), nil }
func (fakeEnc) Open(b []byte) (string, error) { return string(b), nil }

type ikev2Client struct {
	cert, p12pass, address, subnets string
	encKey                          []byte
}

type fakeStore struct {
	caCert  string
	caKey   []byte
	clients map[string]ikev2Client
	revoked []RevokedCert
	crlNum  int64
}

func newFakeStore() *fakeStore { return &fakeStore{clients: map[string]ikev2Client{}} }

func (s *fakeStore) GetCAMaterial(context.Context, string) (string, []byte, string, error) {
	if s.caCert == "" {
		return "", nil, "", fmt.Errorf("none")
	}
	return s.caCert, s.caKey, "internal", nil
}
func (s *fakeStore) SaveCAMaterial(_ context.Context, _, cert string, key []byte, _ string) error {
	s.caCert, s.caKey = cert, key
	return nil
}
func (s *fakeStore) SaveClient(_ context.Context, _, cn, cert string, key []byte, p12pass, address, subnets string) error {
	s.clients[cn] = ikev2Client{cert: cert, encKey: key, p12pass: p12pass, address: address, subnets: subnets}
	return nil
}
func (s *fakeStore) GetClient(_ context.Context, _, cn string) (string, []byte, string, string, string, error) {
	c, ok := s.clients[cn]
	if !ok {
		return "", nil, "", "", "", fmt.Errorf("not found")
	}
	return c.cert, c.encKey, c.p12pass, c.address, c.subnets, nil
}
func (s *fakeStore) ListClients(context.Context, string) ([]string, []string, []string, []string, error) {
	var cns, addrs, subs, pass []string
	for cn, c := range s.clients {
		cns = append(cns, cn)
		addrs = append(addrs, c.address)
		subs = append(subs, c.subnets)
		pass = append(pass, c.p12pass)
	}
	return cns, addrs, subs, pass, nil
}
func (s *fakeStore) DeleteClient(_ context.Context, _, cn string) error {
	delete(s.clients, cn)
	return nil
}
func (s *fakeStore) AddRevokedCert(_ context.Context, _, serial, cn string) error {
	s.revoked = append(s.revoked, RevokedCert{Serial: serial, RevokedAt: time.Now()})
	return nil
}
func (s *fakeStore) ListRevokedCerts(context.Context, string) ([]RevokedCert, error) {
	return s.revoked, nil
}
func (s *fakeStore) NextCRLNumber(context.Context, string) (int64, error) {
	s.crlNum++
	return s.crlNum, nil
}
func (s *fakeStore) SaveServerRoutes(context.Context, string, []string, bool) error { return nil }
func (s *fakeStore) GetServerRoutes(context.Context, string) ([]string, bool, bool, error) {
	// ok=false -- "server not provisioned yet" -- applyClients short-circuits
	// without touching SSH, matching how a bare unit test (no real swanctl
	// config in play) should behave.
	return nil, false, false, nil
}

func testProvider() (*Provider, *fakeStore) {
	st := newFakeStore()
	p := New(Options{SSH: fakeSSH{}, Store: st, Enc: fakeEnc{}})
	return p, st
}

func TestImportPeerAcceptsCertSignedByCurrentCA(t *testing.T) {
	p, st := testProvider()
	ctx := context.Background()
	ca, err := p.getCA(ctx)
	if err != nil {
		t.Fatalf("getCA: %v", err)
	}
	creds, err := ca.IssueClient("adopted-client", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}

	peer, err := p.ImportPeer(ctx, creds.CertPEM, creds.KeyPEM)
	if err != nil {
		t.Fatalf("ImportPeer: %v", err)
	}
	if peer.Name != "adopted-client" {
		t.Errorf("peer name = %q, want adopted-client", peer.Name)
	}
	c, ok := st.clients["adopted-client"]
	if !ok {
		t.Fatal("client not stored")
	}
	if len(c.encKey) == 0 {
		t.Error("expected the pasted key to be sealed and stored")
	}
	if c.p12pass == "" {
		t.Error("expected a p12 password to be generated when a key was pasted")
	}
}

func TestImportPeerAcceptsCertWithoutKey(t *testing.T) {
	p, st := testProvider()
	ctx := context.Background()
	ca, err := p.getCA(ctx)
	if err != nil {
		t.Fatalf("getCA: %v", err)
	}
	creds, err := ca.IssueClient("keyless-client", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}

	peer, err := p.ImportPeer(ctx, creds.CertPEM, "")
	if err != nil {
		t.Fatalf("ImportPeer without key: %v", err)
	}
	if peer.Name != "keyless-client" {
		t.Errorf("peer name = %q, want keyless-client", peer.Name)
	}
	c := st.clients["keyless-client"]
	if len(c.encKey) != 0 || c.p12pass != "" {
		t.Error("expected no server-held key/p12 password when none was pasted")
	}
}

func TestImportPeerRejectsCertFromDifferentCA(t *testing.T) {
	p, _ := testProvider()
	ctx := context.Background()
	if _, err := p.getCA(ctx); err != nil {
		t.Fatalf("getCA: %v", err)
	}
	foreignCA, err := pki.NewInternalCA(time.Hour)
	if err != nil {
		t.Fatalf("NewInternalCA: %v", err)
	}
	creds, err := foreignCA.IssueClient("impostor", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}

	if _, err := p.ImportPeer(ctx, creds.CertPEM, creds.KeyPEM); err == nil {
		t.Error("expected ImportPeer to reject a cert signed by a different CA")
	}
}

func TestImportPeerRejectsMismatchedKey(t *testing.T) {
	p, _ := testProvider()
	ctx := context.Background()
	ca, err := p.getCA(ctx)
	if err != nil {
		t.Fatalf("getCA: %v", err)
	}
	creds, err := ca.IssueClient("mismatched", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	other, err := ca.IssueClient("other", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}

	if _, err := p.ImportPeer(ctx, creds.CertPEM, other.KeyPEM); err == nil {
		t.Error("expected ImportPeer to reject a key that doesn't match the certificate")
	}
}
