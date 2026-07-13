package openvpn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"protean/internal/vpn"
)

type fakeSSH struct{ files map[string]string }

func (f *fakeSSH) Run(context.Context, string) (string, error) { return "", nil }
func (f *fakeSSH) ReadFile(_ context.Context, p string) (string, error) {
	if v, ok := f.files[p]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no such file %s", p)
}
func (f *fakeSSH) WriteFile(_ context.Context, p, c string) error {
	if f.files == nil {
		f.files = map[string]string{}
	}
	f.files[p] = c
	return nil
}

type fakeEnc struct{}

func (fakeEnc) Seal(s string) ([]byte, error) { return []byte(s), nil }
func (fakeEnc) Open(b []byte) (string, error) { return string(b), nil }

type fakeStore struct {
	caCert  string
	caKey   []byte
	clients map[string]OpenVPNClient
	revoked []RevokedCert
	crlNum  int64
}

type OpenVPNClient struct {
	cert    string
	encKey  []byte
	address string
	subnets string
}

func newFakeStore() *fakeStore { return &fakeStore{clients: map[string]OpenVPNClient{}} }

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
func (s *fakeStore) SaveOpenVPNClient(_ context.Context, _, cn, cert string, key []byte, addr, sub string) error {
	s.clients[cn] = OpenVPNClient{cert: cert, encKey: key, address: addr, subnets: sub}
	return nil
}
func (s *fakeStore) GetOpenVPNClient(_ context.Context, _, cn string) (string, []byte, string, string, error) {
	c, ok := s.clients[cn]
	if !ok {
		return "", nil, "", "", fmt.Errorf("not found")
	}
	return c.cert, c.encKey, c.address, c.subnets, nil
}
func (s *fakeStore) ListOpenVPNClients(context.Context, string) ([]string, []string, []string, error) {
	var cns, addrs, subs []string
	for cn, c := range s.clients {
		cns = append(cns, cn)
		addrs = append(addrs, c.address)
		subs = append(subs, c.subnets)
	}
	return cns, addrs, subs, nil
}
func (s *fakeStore) DeleteOpenVPNClient(_ context.Context, _, cn string) error {
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

func testProvider() (*Provider, *fakeSSH, *fakeStore) {
	ssh := &fakeSSH{files: map[string]string{}}
	st := newFakeStore()
	p := New(Options{
		Interface: "server", ServerDir: "/etc/openvpn/server", CCDDir: "/etc/openvpn/server/ccd",
		ServiceName: "openvpn-server@server", ServerMask: "255.255.255.0",
		SSH: ssh, Store: st, Enc: fakeEnc{},
	})
	return p, ssh, st
}

func makeCSR(t *testing.T, cn string) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestAddPeerFromCSRStoresCertWithoutKey(t *testing.T) {
	p, _, st := testProvider()
	ctx := context.Background()
	_, err := p.AddPeerFromCSR(ctx, makeCSR(t, "office"), vpn.PeerSpec{Name: "office", AllowedIPs: []string{"10.8.0.5/32"}})
	if err != nil {
		t.Fatalf("AddPeerFromCSR: %v", err)
	}
	c := st.clients["office"]
	if c.cert == "" {
		t.Error("cert not stored")
	}
	if len(c.encKey) != 0 {
		t.Error("CSR-based client must have no server-held key")
	}
}

func TestEnsureServerWritesTunMTUAndMssfix(t *testing.T) {
	ssh := &fakeSSH{files: map[string]string{}}
	p := New(Options{
		Interface: "server", ConfPath: "/etc/openvpn/server/server.conf",
		ServerDir: "/etc/openvpn/server", CCDDir: "/etc/openvpn/server/ccd",
		ServiceName: "openvpn-server@server", ServerNet: "10.8.0.0", ServerMask: "255.255.255.0",
		MTU: 1400, Mssfix: 1350,
		SSH: ssh, Store: newFakeStore(), Enc: fakeEnc{},
	})
	if err := p.EnsureServer(context.Background(), nil, false); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	conf := ssh.files["/etc/openvpn/server/server.conf"]
	if !strings.Contains(conf, "tun-mtu 1400") || !strings.Contains(conf, "mssfix 1350") {
		t.Errorf("server conf missing tun-mtu/mssfix:\n%s", conf)
	}
}

func TestEnsureServerOmitsTunMTUAndMssfixWhenUnset(t *testing.T) {
	p, ssh, _ := testProvider()
	p.opts.ConfPath = "/etc/openvpn/server/server.conf"
	p.opts.ServerNet, p.opts.ServerMask = "10.8.0.0", "255.255.255.0"
	if err := p.EnsureServer(context.Background(), nil, false); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	conf := ssh.files["/etc/openvpn/server/server.conf"]
	if strings.Contains(conf, "tun-mtu") || strings.Contains(conf, "mssfix") {
		t.Errorf("expected no tun-mtu/mssfix line when unset:\n%s", conf)
	}
}

func TestRemovePeerRevokesCert(t *testing.T) {
	p, ssh, st := testProvider()
	ctx := context.Background()
	if _, err := p.AddPeer(ctx, vpn.PeerSpec{Name: "gone", AllowedIPs: []string{"10.8.0.6/32"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := p.RemovePeer(ctx, "gone"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if len(st.revoked) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(st.revoked))
	}
	crl, ok := ssh.files["/etc/openvpn/server/crl.pem"]
	if !ok || !strings.Contains(crl, "X509 CRL") {
		t.Errorf("CRL not written to host: %q", crl)
	}
	if _, ok := st.clients["gone"]; ok {
		t.Error("client should be deleted after revoke")
	}
}
