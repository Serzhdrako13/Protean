//go:build e2eload

package loadtest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"protean/internal/sshexec"
	"protean/internal/vpn/openvpn"
)

type ovpnClient struct {
	cert, addr, subnets string
	encKey              []byte
}

type fakeOpenVPNStore struct {
	mu      sync.Mutex
	caCert  string
	caKey   []byte
	clients map[string]ovpnClient
	revoked []openvpn.RevokedCert
	crlNum  int64
}

func newFakeOpenVPNStore() *fakeOpenVPNStore {
	return &fakeOpenVPNStore{clients: map[string]ovpnClient{}}
}

func (s *fakeOpenVPNStore) GetCAMaterial(context.Context, string) (string, []byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caCert == "" {
		return "", nil, "", fmt.Errorf("none")
	}
	return s.caCert, s.caKey, "internal", nil
}
func (s *fakeOpenVPNStore) SaveCAMaterial(_ context.Context, _, cert string, key []byte, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caCert, s.caKey = cert, key
	return nil
}
func (s *fakeOpenVPNStore) SaveOpenVPNClient(_ context.Context, _, cn, cert string, key []byte, addr, subnets string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[cn] = ovpnClient{cert: cert, encKey: key, addr: addr, subnets: subnets}
	return nil
}
func (s *fakeOpenVPNStore) GetOpenVPNClient(_ context.Context, _, cn string) (string, []byte, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[cn]
	if !ok {
		return "", nil, "", "", fmt.Errorf("not found")
	}
	return c.cert, c.encKey, c.addr, c.subnets, nil
}
func (s *fakeOpenVPNStore) ListOpenVPNClients(context.Context, string) ([]string, []string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cns, addrs, subs []string
	for cn, c := range s.clients {
		cns = append(cns, cn)
		addrs = append(addrs, c.addr)
		subs = append(subs, c.subnets)
	}
	return cns, addrs, subs, nil
}
func (s *fakeOpenVPNStore) DeleteOpenVPNClient(_ context.Context, _, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, cn)
	return nil
}
func (s *fakeOpenVPNStore) AddRevokedCert(_ context.Context, _, serial, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, openvpn.RevokedCert{Serial: serial, RevokedAt: time.Now()})
	return nil
}
func (s *fakeOpenVPNStore) ListRevokedCerts(context.Context, string) ([]openvpn.RevokedCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked, nil
}
func (s *fakeOpenVPNStore) NextCRLNumber(context.Context, string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crlNum++
	return s.crlNum, nil
}

func TestLoadOpenVPN(t *testing.T) {
	ctx := context.Background()
	sshClient := newSSHClient(t)
	store := newFakeOpenVPNStore()
	p := openvpn.New(openvpn.Options{
		Instance: "loadtest:openvpn", Interface: "server",
		ConfPath: "/etc/openvpn/server/server.conf", ServerDir: "/etc/openvpn/server",
		CCDDir: "/etc/openvpn/server/ccd-server", StatusPath: "/run/openvpn-server/status-server.log",
		ServiceName: "openvpn-server@server", PublicHost: serverIP,
		ListenPort: 1194, Proto: "udp", ServerNet: "10.8.0.0", ServerMask: "255.255.255.0",
		SSH: sshClient, Store: store, Enc: fakeSealer{},
	})
	if err := p.EnsureServer(ctx, nil, false); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	assertActive(t, ctx, sshClient, "openvpn-server@server")

	for _, n := range concurrencyTiers() {
		n := n
		t.Run(fmt.Sprintf("concurrency=%d", n), func(t *testing.T) {
			r := loadOpenVPNTier(t, ctx, sshClient, p, n)
			recordResult("openvpn", n, r)
		})
	}
}

func loadOpenVPNTier(t *testing.T, ctx context.Context, sshClient *sshexec.Client, p *openvpn.Provider, n int) tierResult {
	t.Helper()
	basePort := 15100
	var peerIDs []string
	var nss []string
	t.Cleanup(func() {
		for _, ns := range nss {
			delPeerNS(ns)
		}
		for _, id := range peerIDs {
			_ = p.RemovePeer(ctx, id)
		}
		_, _ = sshClient.Run(ctx, "pkill -f 'iperf3 -s' || true")
	})

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("ovpn-p%d", i)
		clientAddr := fmt.Sprintf("10.8.0.%d", 10+i)
		res, err := p.AddPeer(ctx, peerSpec(name, clientAddr+"/32"))
		if err != nil {
			t.Fatalf("AddPeer %d: %v", i, err)
		}
		peerIDs = append(peerIDs, res.Peer.ID)

		_, bundle, err := p.ClientConfigFile(ctx, name)
		if err != nil {
			t.Fatalf("ClientConfigFile %d: %v", i, err)
		}

		ns := fmt.Sprintf("ov%d", i)
		newPeerNS(t, ns, 60+i) // offset so veth subnets don't collide with WireGuard's tier
		nss = append(nss, ns)

		confPath := fmt.Sprintf("/tmp/%s.ovpn", ns)
		clientWriteFile(t, confPath, string(bundle))
		clientExecNS(t, ns, fmt.Sprintf(
			"openvpn --config %s --daemon --writepid /tmp/%s.pid --log /tmp/%s.ovpnlog", confPath, ns, ns))

		port := basePort + i
		if _, err := sshClient.Run(ctx, fmt.Sprintf("iperf3 -s -p %d -B 10.8.0.1 -D", port)); err != nil {
			t.Fatalf("start iperf3 server %d: %v", i, err)
		}
	}

	// Real TLS handshake + key exchange needs a few seconds, more so at
	// higher concurrency against one server process.
	time.Sleep(time.Duration(3+n/5) * time.Second)

	return runIperfTier(t, nss, "10.8.0.1", basePort, "openvpn")
}
