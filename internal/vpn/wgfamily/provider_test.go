package wgfamily

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"protean/internal/vpn"
)

// fakeSSH simulates the host: it holds the config file in memory and, on
// every ReadFile/WriteFile, sleeps a beat while NOT holding its own lock, so
// that if the provider didn't serialize its read-modify-write, concurrent
// AddPeer calls would interleave and lose peers (the classic lost-update).
type fakeSSH struct {
	mu      sync.Mutex
	conf    string
	iface   string
	applied map[string]bool // peers applied live via `wg set`
}

func newFakeSSH() *fakeSSH {
	return &fakeSSH{
		conf:    "[Interface]\nPrivateKey = k\nAddress = 10.0.0.1/24\nListenPort = 51820\n",
		applied: map[string]bool{},
	}
}

func (f *fakeSSH) InterfaceExists(context.Context, string) bool { return true }

func (f *fakeSSH) ReadFile(context.Context, string) (string, error) {
	f.mu.Lock()
	c := f.conf
	f.mu.Unlock()
	// Yield to make interleaving likely under -race if unlocked.
	for i := 0; i < 100; i++ {
		_ = i
	}
	return c, nil
}

func (f *fakeSSH) WriteFile(_ context.Context, _ string, content string) error {
	for i := 0; i < 100; i++ {
		_ = i
	}
	f.mu.Lock()
	f.conf = content
	f.mu.Unlock()
	return nil
}

func (f *fakeSSH) Run(_ context.Context, cmd string) (string, error) {
	// Emulate `wg set <iface> peer <pk> ...` recording live peer state.
	if strings.Contains(cmd, " set ") && strings.Contains(cmd, " peer ") {
		return "", nil
	}
	return "", nil
}

func testProvider(f *fakeSSH) *Provider {
	return New(Options{
		ProviderName: "wireguard",
		Interface:    "wg0",
		ConfPath:     "/etc/wireguard/wg0.conf",
		Binary:       "wg",
		ServiceName:  "wg-quick@wg0",
		SSH:          f,
	})
}

func TestAddConfiguredPeer(t *testing.T) {
	f := newFakeSSH()
	p := testProvider(f)

	const pk = "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoM="
	spec := vpn.PeerSpec{Name: "revived", AllowedIPs: []string{"10.0.0.7/32"}, PersistentKeepalive: 25}
	if err := p.AddConfiguredPeer(context.Background(), pk, spec); err != nil {
		t.Fatalf("AddConfiguredPeer: %v", err)
	}

	cf := ParseConf(f.conf)
	cp := cf.FindPeer(pk)
	if cp == nil {
		t.Fatal("configured peer not written to conf")
	}
	if cp.Name != "revived" {
		t.Errorf("name = %q", cp.Name)
	}

	// Adding it again must fail (already present) -- no silent duplicate.
	if err := p.AddConfiguredPeer(context.Background(), pk, spec); err == nil {
		t.Error("expected error re-adding an already-present peer")
	}
}

func TestRotatePeerKey(t *testing.T) {
	f := newFakeSSH()
	p := testProvider(f)

	orig, err := p.AddPeer(context.Background(), vpn.PeerSpec{
		Name:                "office-a",
		AllowedIPs:          []string{"10.0.0.2/32", "192.168.5.0/24"},
		PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	rot, err := p.RotatePeerKey(context.Background(), orig.Peer.PublicKey)
	if err != nil {
		t.Fatalf("RotatePeerKey: %v", err)
	}

	if rot.Peer.PublicKey == orig.Peer.PublicKey {
		t.Error("public key did not change after rotation")
	}
	if rot.PrivateKey == "" || rot.PrivateKey == orig.PrivateKey {
		t.Error("private key not regenerated")
	}
	if rot.Peer.Name != "office-a" {
		t.Errorf("name not preserved: %q", rot.Peer.Name)
	}
	if len(rot.Peer.AllowedIPs) != 2 || rot.Peer.PersistentKeepalive != 25 {
		t.Errorf("routing/keepalive not preserved: %+v", rot.Peer)
	}

	// Config must contain exactly one peer: the new key, not the old.
	cf := ParseConf(f.conf)
	if len(cf.Peers) != 1 {
		t.Fatalf("expected 1 peer after rotation, got %d", len(cf.Peers))
	}
	if cf.FindPeer(orig.Peer.PublicKey) != nil {
		t.Error("old peer still in config after rotation")
	}
	if cf.FindPeer(rot.Peer.PublicKey) == nil {
		t.Error("new peer missing from config after rotation")
	}
}

// TestConcurrentAddPeerNoLostUpdate adds many peers concurrently; with the
// per-provider lock, every one must end up in the config. Run with -race.
func TestConcurrentAddPeerNoLostUpdate(t *testing.T) {
	f := newFakeSSH()
	p := testProvider(f)

	const n = 25
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.AddPeer(context.Background(), vpn.PeerSpec{
				Name:       fmt.Sprintf("peer-%d", i),
				AllowedIPs: []string{fmt.Sprintf("10.0.0.%d/32", i+2)},
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
	}

	cf := ParseConf(f.conf)
	if len(cf.Peers) != n {
		t.Fatalf("expected %d peers after concurrent adds, got %d (lost-update race)", n, len(cf.Peers))
	}
}

func TestUpdateServerConfigMTU(t *testing.T) {
	f := newFakeSSH()
	p := testProvider(f)
	ctx := context.Background()

	if err := p.UpdateServerConfig(ctx, vpn.ServerConfig{ListenPort: 51820, Address: "10.0.0.1/24", MTU: 1280}); err != nil {
		t.Fatalf("UpdateServerConfig: %v", err)
	}
	if !strings.Contains(f.conf, "MTU = 1280") {
		t.Errorf("conf missing MTU line after setting it:\n%s", f.conf)
	}

	// Clearing (MTU: 0) must remove the line entirely, not write "MTU = 0"
	// (which wg-quick rejects).
	if err := p.UpdateServerConfig(ctx, vpn.ServerConfig{ListenPort: 51820, Address: "10.0.0.1/24", MTU: 0}); err != nil {
		t.Fatalf("UpdateServerConfig (clear): %v", err)
	}
	if strings.Contains(f.conf, "MTU") {
		t.Errorf("conf should have no MTU line after clearing it:\n%s", f.conf)
	}
}
