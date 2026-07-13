package api

// Exercises buildDashboardView's actual logic (peer sorting, peer ID
// encoding, ErrNotImplemented handling) against an in-memory fake
// provider -- no SSH host or database required.

import (
	"context"
	"net/http/httptest"
	"testing"

	"protean/internal/vpn"
)

type fakeProvider struct {
	name   string
	status vpn.ServerStatus
	peers  []vpn.Peer
	err    error
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Type() string { return f.name }
func (f *fakeProvider) Status(ctx context.Context) (vpn.ServerStatus, error) {
	return f.status, f.err
}
func (f *fakeProvider) ListPeers(ctx context.Context) ([]vpn.Peer, error) { return f.peers, nil }
func (f *fakeProvider) AddPeer(ctx context.Context, spec vpn.PeerSpec) (vpn.NewPeerResult, error) {
	return vpn.NewPeerResult{}, vpn.ErrNotImplemented
}
func (f *fakeProvider) UpdatePeer(ctx context.Context, id string, spec vpn.PeerSpec) error {
	return vpn.ErrNotImplemented
}
func (f *fakeProvider) RemovePeer(ctx context.Context, id string) error { return vpn.ErrNotImplemented }
func (f *fakeProvider) UpdateServerConfig(ctx context.Context, cfg vpn.ServerConfig) error {
	return vpn.ErrNotImplemented
}

func TestBuildDashboardViewSortsAndEncodesPeers(t *testing.T) {
	// Valid standard-base64-encoded 32-byte keys, distinct, so sort order
	// is verifiable and peer-id round-tripping is exercised for real keys.
	const keyZeta = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	const keyAlpha = "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoM="

	reg := vpn.NewRegistry()
	reg.Register(&fakeProvider{
		name: "wireguard",
		status: vpn.ServerStatus{
			Up: true, Address: "10.10.0.1/24", PeerCount: 2, PeersOnline: 1,
		},
		peers: []vpn.Peer{
			{PublicKey: keyZeta, Name: "zeta"},
			{PublicKey: keyAlpha, Name: "alpha", Online: true},
		},
	})

	s := &Server{reg: reg}
	req := httptest.NewRequest("GET", "/providers/wireguard", nil)

	view, err := s.buildAPIProviderDetail(req, "wireguard")
	if err != nil {
		t.Fatalf("buildDashboardView: %v", err)
	}
	if len(view.Peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(view.Peers))
	}
	if view.Peers[0].Name != "alpha" || view.Peers[1].Name != "zeta" {
		t.Errorf("peers not sorted by name: %+v", view.Peers)
	}
	if !view.Peers[0].Online {
		t.Error("alpha should be online")
	}

	// URL IDs must round-trip back to the original public key.
	for i, p := range view.Peers {
		decoded, err := decodePeerID(p.URLID)
		if err != nil {
			t.Fatalf("decodePeerID(%q): %v", p.URLID, err)
		}
		want := []string{keyAlpha, keyZeta}[i]
		if decoded != want {
			t.Errorf("peer %d: decodePeerID round trip = %q, want %q", i, decoded, want)
		}
	}
}

func TestBuildDashboardViewNotImplemented(t *testing.T) {
	reg := vpn.NewRegistry()
	reg.Register(&fakeProvider{name: "openvpn", err: vpn.ErrNotImplemented})

	s := &Server{reg: reg}
	req := httptest.NewRequest("GET", "/providers/openvpn", nil)

	view, err := s.buildAPIProviderDetail(req, "openvpn")
	if err != nil {
		t.Fatalf("buildDashboardView: %v", err)
	}
	if !view.NotImplemented {
		t.Error("expected NotImplemented = true")
	}
}

func TestBuildDashboardViewDownInterface(t *testing.T) {
	reg := vpn.NewRegistry()
	reg.Register(&fakeProvider{name: "wireguard", status: vpn.ServerStatus{Up: false}})

	s := &Server{reg: reg}
	req := httptest.NewRequest("GET", "/providers/wireguard", nil)

	view, err := s.buildAPIProviderDetail(req, "wireguard")
	if err != nil {
		t.Fatalf("buildDashboardView: %v", err)
	}
	if view.Status.Up {
		t.Error("expected Up = false")
	}
	if len(view.Peers) != 0 {
		t.Error("expected no peers when interface is down")
	}
}

func TestBuildDashboardViewUnknownProvider(t *testing.T) {
	s := &Server{reg: vpn.NewRegistry()}
	req := httptest.NewRequest("GET", "/providers/nope", nil)

	if _, err := s.buildAPIProviderDetail(req, "nope"); err == nil {
		t.Error("expected error for unknown provider")
	}
}
