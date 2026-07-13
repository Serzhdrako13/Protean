package wgfamily

import (
	"strings"
	"testing"
)

const sampleConf = `[Interface]
PrivateKey = serverpriv
Address = 10.10.0.1/24
ListenPort = 51820

# Name: office-a
[Peer]
PublicKey = peerpub1
AllowedIPs = 10.10.0.2/32, 192.168.1.0/24
PersistentKeepalive = 25

[Peer]
PublicKey = peerpub2
AllowedIPs = 10.10.0.3/32
`

func TestParseConf(t *testing.T) {
	cf := ParseConf(sampleConf)

	if addr, _ := cf.InterfaceGet("Address"); addr != "10.10.0.1/24" {
		t.Errorf("Address = %q", addr)
	}
	if port, _ := cf.InterfaceGet("ListenPort"); port != "51820" {
		t.Errorf("ListenPort = %q", port)
	}

	if len(cf.Peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(cf.Peers))
	}
	if cf.Peers[0].Name != "office-a" {
		t.Errorf("peer[0].Name = %q, want office-a", cf.Peers[0].Name)
	}
	if cf.Peers[1].Name != "" {
		t.Errorf("peer[1].Name = %q, want empty (no comment)", cf.Peers[1].Name)
	}

	p := cf.FindPeer("peerpub1")
	if p == nil {
		t.Fatal("FindPeer(peerpub1) = nil")
	}
	if v, _ := getOpt(p.Opts, "AllowedIPs"); v != "10.10.0.2/32, 192.168.1.0/24" {
		t.Errorf("peer1 AllowedIPs = %q", v)
	}
}

func TestConfAddRemoveReplace(t *testing.T) {
	cf := ParseConf(sampleConf)

	cf.AddPeer(ConfPeer{Name: "new-client", Opts: []KV{
		{Key: "PublicKey", Value: "peerpub3"},
		{Key: "AllowedIPs", Value: "10.10.0.4/32"},
	}})
	if len(cf.Peers) != 3 {
		t.Fatalf("after AddPeer: got %d peers, want 3", len(cf.Peers))
	}
	if cf.FindPeer("peerpub3") == nil {
		t.Fatal("FindPeer(peerpub3) = nil after AddPeer")
	}

	ok := cf.ReplacePeer("peerpub3", ConfPeer{Name: "renamed", Opts: []KV{
		{Key: "PublicKey", Value: "peerpub3"},
		{Key: "AllowedIPs", Value: "10.10.0.4/32"},
	}})
	if !ok {
		t.Fatal("ReplacePeer(peerpub3) returned false")
	}
	if cf.FindPeer("peerpub3").Name != "renamed" {
		t.Errorf("after ReplacePeer, Name = %q, want renamed", cf.FindPeer("peerpub3").Name)
	}

	if !cf.RemovePeer("peerpub3") {
		t.Fatal("RemovePeer(peerpub3) returned false")
	}
	if cf.FindPeer("peerpub3") != nil {
		t.Error("FindPeer(peerpub3) still found after RemovePeer")
	}
	if len(cf.Peers) != 2 {
		t.Fatalf("after RemovePeer: got %d peers, want 2", len(cf.Peers))
	}
}

func TestConfRenderRoundTrip(t *testing.T) {
	cf := ParseConf(sampleConf)
	rendered := cf.Render()

	reparsed := ParseConf(rendered)
	if len(reparsed.Peers) != len(cf.Peers) {
		t.Fatalf("round trip peer count = %d, want %d", len(reparsed.Peers), len(cf.Peers))
	}
	if reparsed.Peers[0].Name != "office-a" {
		t.Errorf("round trip peer[0].Name = %q", reparsed.Peers[0].Name)
	}
	if addr, _ := reparsed.InterfaceGet("Address"); addr != "10.10.0.1/24" {
		t.Errorf("round trip Address = %q", addr)
	}
}

func TestManagedForwardingIptables(t *testing.T) {
	cf := ParseConf(sampleConf)
	if cf.HasManagedForwarding() {
		t.Fatal("fresh conf should not have managed forwarding")
	}

	cf.SetManagedNetworking(BackendIptables, true, false, "", "")
	if !cf.HasManagedForwarding() {
		t.Fatal("expected managed forwarding after enabling")
	}
	if cf.HasManagedNAT() {
		t.Error("forwarding-only must not add NAT")
	}
	// Idempotent: re-applying keeps the same rule count.
	before := countManaged(cf)
	cf.SetManagedNetworking(BackendIptables, true, false, "", "")
	if countManaged(cf) != before {
		t.Error("SetManagedNetworking not idempotent")
	}

	// Survives render/reparse; interface settings intact.
	reparsed := ParseConf(cf.Render())
	if !reparsed.HasManagedForwarding() {
		t.Error("managed forwarding lost across round trip")
	}
	if addr, _ := reparsed.InterfaceGet("Address"); addr != "10.10.0.1/24" {
		t.Errorf("Address corrupted: %q", addr)
	}

	cf.SetManagedNetworking(BackendIptables, false, false, "", "")
	if cf.HasManagedForwarding() {
		t.Error("expected no managed rules after disabling")
	}
}

func TestManagedForwardingNoMasquerade(t *testing.T) {
	cf := ParseConf(sampleConf)
	cf.SetManagedNetworking(BackendIptables, true, false, "", "")
	if strings.Contains(strings.ToUpper(cf.Render()), "MASQUERADE") {
		t.Error("forwarding-only rules must not MASQUERADE")
	}
}

func TestManagedNATIptables(t *testing.T) {
	cf := ParseConf(sampleConf)
	cf.SetManagedNetworking(BackendIptables, true, true, "10.10.0.0/24", "eth0")
	if !cf.HasManagedNAT() {
		t.Fatal("expected NAT after enabling egress")
	}
	r := cf.Render()
	if !strings.Contains(r, "MASQUERADE") || !strings.Contains(r, "10.10.0.0/24") || !strings.Contains(r, "-o eth0") {
		t.Errorf("NAT rule not rendered correctly:\n%s", r)
	}
	// Turning egress off keeps forwarding, drops NAT.
	cf.SetManagedNetworking(BackendIptables, true, false, "", "")
	if cf.HasManagedNAT() {
		t.Error("NAT should be gone after egress off")
	}
	if !cf.HasManagedForwarding() {
		t.Error("forwarding must remain after egress off")
	}
}

func TestManagedNftBackend(t *testing.T) {
	cf := ParseConf(sampleConf)
	cf.SetManagedNetworking(BackendNft, true, true, "10.10.0.0/24", "eth0")
	r := cf.Render()
	if !strings.Contains(r, "nft add table inet protean_%i") {
		t.Errorf("nft table rule missing:\n%s", r)
	}
	if !strings.Contains(r, "masquerade") {
		t.Errorf("nft masquerade missing:\n%s", r)
	}
	if !strings.Contains(r, "nft delete table inet protean_%i") {
		t.Errorf("nft teardown missing:\n%s", r)
	}
	if !cf.HasManagedForwarding() || !cf.HasManagedNAT() {
		t.Error("nft rules not detected by Has* helpers")
	}
	// Switching backends must not leave stale rules from the other backend.
	cf.SetManagedNetworking(BackendIptables, true, false, "", "")
	if strings.Contains(cf.Render(), "nft ") {
		t.Error("stale nft rules left after switching to iptables")
	}
}

func countManaged(cf *ConfFile) int {
	n := 0
	for _, kv := range cf.InterfaceOpts {
		if isManagedRule(kv) {
			n++
		}
	}
	return n
}

func TestConfNameInjectionIsSanitized(t *testing.T) {
	cf := &ConfFile{
		InterfaceOpts: []KV{{Key: "Address", Value: "10.10.0.1/24"}},
		Peers: []ConfPeer{{
			Name: "evil\n[Interface]\nPrivateKey = hijacked",
			Opts: []KV{{Key: "PublicKey", Value: "peerpub1"}},
		}},
	}
	rendered := cf.Render()

	reparsed := ParseConf(rendered)
	if len(reparsed.Peers) != 1 {
		t.Fatalf("name injection produced %d peers, want 1", len(reparsed.Peers))
	}
	if addr, _ := reparsed.InterfaceGet("PrivateKey"); addr != "" {
		t.Errorf("name injection leaked a PrivateKey into [Interface]: %q", addr)
	}
}
