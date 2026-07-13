package wgfamily

import (
	"testing"
	"time"
)

const sampleDump = "serverpriv\tserverpub\t51820\toff\n" +
	"peerpub1\t(none)\t203.0.113.5:51820\t10.10.0.2/32\t1700000000\t1000\t2000\t25\n" +
	"peerpub2\t(none)\t(none)\t10.10.0.3/32,192.168.1.0/24\t0\t0\t0\toff\n"

func TestParseDump(t *testing.T) {
	iface, peers, err := ParseDump(sampleDump)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}

	if iface.PrivateKey != "serverpriv" || iface.PublicKey != "serverpub" {
		t.Errorf("interface keys = %+v", iface)
	}
	if iface.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", iface.ListenPort)
	}

	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(peers))
	}

	p1 := peers[0]
	if p1.PublicKey != "peerpub1" {
		t.Errorf("peer1 PublicKey = %q", p1.PublicKey)
	}
	if p1.Endpoint != "203.0.113.5:51820" {
		t.Errorf("peer1 Endpoint = %q", p1.Endpoint)
	}
	if len(p1.AllowedIPs) != 1 || p1.AllowedIPs[0] != "10.10.0.2/32" {
		t.Errorf("peer1 AllowedIPs = %v", p1.AllowedIPs)
	}
	if !p1.LatestHandshake.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("peer1 LatestHandshake = %v", p1.LatestHandshake)
	}
	if p1.RxBytes != 1000 || p1.TxBytes != 2000 {
		t.Errorf("peer1 rx/tx = %d/%d", p1.RxBytes, p1.TxBytes)
	}
	if p1.PersistentKeepalive != 25 {
		t.Errorf("peer1 PersistentKeepalive = %d", p1.PersistentKeepalive)
	}

	p2 := peers[1]
	if p2.Endpoint != "" {
		t.Errorf("peer2 Endpoint = %q, want empty (none)", p2.Endpoint)
	}
	if !p2.LatestHandshake.IsZero() {
		t.Errorf("peer2 LatestHandshake = %v, want zero", p2.LatestHandshake)
	}
	if p2.PersistentKeepalive != 0 {
		t.Errorf("peer2 PersistentKeepalive = %d, want 0 for off", p2.PersistentKeepalive)
	}
	if len(p2.AllowedIPs) != 2 || p2.AllowedIPs[1] != "192.168.1.0/24" {
		t.Errorf("peer2 AllowedIPs = %v", p2.AllowedIPs)
	}
}

func TestParseDumpEmpty(t *testing.T) {
	if _, _, err := ParseDump(""); err == nil {
		t.Error("expected error for empty dump output")
	}
}
