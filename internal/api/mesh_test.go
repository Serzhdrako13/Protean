package api

import (
	"context"
	"sort"
	"testing"

	"protean/internal/vpn"
)

// meshFakeProvider is a minimal vpn.Provider for exercising mesh routing.
type meshFakeProvider struct {
	name    string
	address string
}

func (f *meshFakeProvider) Name() string { return f.name }
func (f *meshFakeProvider) Type() string { return f.name }
func (f *meshFakeProvider) Status(context.Context) (vpn.ServerStatus, error) {
	return vpn.ServerStatus{Provider: f.name, Up: true, Address: f.address}, nil
}
func (f *meshFakeProvider) ListPeers(context.Context) ([]vpn.Peer, error) { return nil, nil }
func (f *meshFakeProvider) AddPeer(context.Context, vpn.PeerSpec) (vpn.NewPeerResult, error) {
	return vpn.NewPeerResult{}, vpn.ErrNotImplemented
}
func (f *meshFakeProvider) UpdatePeer(context.Context, string, vpn.PeerSpec) error {
	return vpn.ErrNotImplemented
}
func (f *meshFakeProvider) RemovePeer(context.Context, string) error { return vpn.ErrNotImplemented }
func (f *meshFakeProvider) UpdateServerConfig(context.Context, vpn.ServerConfig) error {
	return vpn.ErrNotImplemented
}

func TestMeshTunnelCIDRs(t *testing.T) {
	reg := vpn.NewRegistry()
	reg.Register(&meshFakeProvider{name: "wireguard", address: "10.10.0.1/24"})
	reg.Register(&meshFakeProvider{name: "amneziawg", address: "10.20.0.1/24"})
	st := &Server{reg: reg}

	tunnels := st.allTunnelCIDRs(context.Background(), "")
	sort.Strings(tunnels)
	if len(tunnels) != 2 || tunnels[0] != "10.10.0.0/24" || tunnels[1] != "10.20.0.0/24" {
		t.Fatalf("allTunnelCIDRs = %v, want both tunnel networks", tunnels)
	}
}

func TestComputeRoutes(t *testing.T) {
	// A WireGuard peer at 10.10.0.5 that itself serves 192.168.5.0/24.
	peer := vpn.Peer{
		Provider:   "wireguard",
		AllowedIPs: []string{"10.10.0.5/32", "192.168.5.0/24"},
	}
	tunnels := []string{"10.10.0.0/24", "10.20.0.0/24"}
	subnets := []string{"192.168.5.0/24", "192.168.6.0/24"} // own + a remote site

	// No egress: specific routes, own subnet excluded, no default route.
	routes := computeRoutes(peer, tunnels, subnets, false)
	got := map[string]bool{}
	for _, r := range routes {
		got[r] = true
	}
	for _, want := range []string{"10.10.0.0/24", "10.20.0.0/24", "192.168.6.0/24"} {
		if !got[want] {
			t.Errorf("routes missing %s; got %v", want, routes)
		}
	}
	if got["192.168.5.0/24"] {
		t.Errorf("routes should exclude the peer's own subnet; got %v", routes)
	}
	if got["0.0.0.0/0"] {
		t.Errorf("no egress requested but default route present; got %v", routes)
	}
	if len(routes) != len(got) {
		t.Errorf("routes contain duplicates: %v", routes)
	}

	// Egress: default route added.
	eg := computeRoutes(peer, tunnels, subnets, true)
	hasDefault := false
	for _, r := range eg {
		if r == "0.0.0.0/0" {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Errorf("egress requested but no default route; got %v", eg)
	}
}

func TestTunnelNetworkDualStack(t *testing.T) {
	// Address may be a comma-separated dual-stack list; use the IPv4 entry.
	got, ok := tunnelNetwork("10.10.0.1/24, fd00::1/64")
	if !ok || got != "10.10.0.0/24" {
		t.Errorf("tunnelNetwork(dual-stack) = %q,%v; want 10.10.0.0/24", got, ok)
	}
	if vpn.FirstCIDR(" 10.10.0.1/24 , fd00::1/64 ") != "10.10.0.1/24" {
		t.Errorf("firstCIDR trim/split wrong: %q", vpn.FirstCIDR(" 10.10.0.1/24 , fd00::1/64 "))
	}
}

func TestTunnelNetwork(t *testing.T) {
	got, ok := tunnelNetwork("10.10.0.1/24")
	if !ok || got != "10.10.0.0/24" {
		t.Errorf("tunnelNetwork(10.10.0.1/24) = %q,%v", got, ok)
	}
	if _, ok := tunnelNetwork("garbage"); ok {
		t.Error("expected failure on garbage input")
	}
}
