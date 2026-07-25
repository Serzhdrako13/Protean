package vpn

import "testing"

func TestClassifyPeerRoutesPlainClient(t *testing.T) {
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"10.10.0.5/32"})
	if c.OwnAddress != "10.10.0.5/32" {
		t.Errorf("OwnAddress = %q", c.OwnAddress)
	}
	if len(c.SiteSubnets) != 0 || c.FullTunnel || len(c.Anomalies) != 0 {
		t.Errorf("unexpected extras: %+v", c)
	}
}

func TestClassifyPeerRoutesFullTunnelClient(t *testing.T) {
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"10.10.0.5/32", "0.0.0.0/0"})
	if c.OwnAddress != "10.10.0.5/32" {
		t.Errorf("OwnAddress = %q", c.OwnAddress)
	}
	if !c.FullTunnel {
		t.Error("FullTunnel = false, want true")
	}
	if len(c.SiteSubnets) != 0 {
		t.Errorf("0.0.0.0/0 leaked into SiteSubnets: %v", c.SiteSubnets)
	}
}

func TestClassifyPeerRoutesRouterWithSubnet(t *testing.T) {
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"10.10.0.9/32", "192.168.50.0/24"})
	if c.OwnAddress != "10.10.0.9/32" {
		t.Errorf("OwnAddress = %q", c.OwnAddress)
	}
	if len(c.SiteSubnets) != 1 || c.SiteSubnets[0] != "192.168.50.0/24" {
		t.Errorf("SiteSubnets = %v", c.SiteSubnets)
	}
	if len(c.Anomalies) != 0 {
		t.Errorf("unexpected anomalies: %v", c.Anomalies)
	}
}

// A hand-written conf has no ordering convention -- the site subnet can
// legitimately appear before the peer's own address. Must classify the
// same as the reverse order.
func TestClassifyPeerRoutesSubnetBeforeOwnAddress(t *testing.T) {
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"192.168.50.0/24", "10.10.0.9/32"})
	if c.OwnAddress != "10.10.0.9/32" {
		t.Errorf("OwnAddress = %q", c.OwnAddress)
	}
	if len(c.SiteSubnets) != 1 || c.SiteSubnets[0] != "192.168.50.0/24" {
		t.Errorf("SiteSubnets = %v", c.SiteSubnets)
	}
}

func TestClassifyPeerRoutesMissingOwnAddress(t *testing.T) {
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"192.168.50.0/24"})
	if c.OwnAddress != "" {
		t.Errorf("OwnAddress = %q, want empty", c.OwnAddress)
	}
	if len(c.SiteSubnets) != 1 {
		t.Errorf("SiteSubnets = %v", c.SiteSubnets)
	}
}

func TestClassifyPeerRoutesDualOwnAddressCandidate(t *testing.T) {
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"10.10.0.5/32", "10.10.0.6/32"})
	if c.OwnAddress != "10.10.0.5/32" {
		t.Errorf("OwnAddress = %q, want first candidate kept", c.OwnAddress)
	}
	if len(c.Anomalies) != 1 {
		t.Fatalf("Anomalies = %v, want exactly 1", c.Anomalies)
	}
}

func TestClassifyPeerRoutesMalformedEntry(t *testing.T) {
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"10.10.0.5/32", "not-a-cidr"})
	if c.OwnAddress != "10.10.0.5/32" {
		t.Errorf("OwnAddress = %q", c.OwnAddress)
	}
	if len(c.Anomalies) != 1 {
		t.Fatalf("Anomalies = %v, want exactly 1 (malformed entry, no crash)", c.Anomalies)
	}
}

func TestClassifyPeerRoutesWideEntryInsideTunnel(t *testing.T) {
	// A peer claiming a chunk of the tunnel network itself -- unusual, not
	// auto-classified as either an address or a site subnet.
	c := ClassifyPeerRoutes("10.10.0.0/24", []string{"10.10.0.5/32", "10.10.0.128/25"})
	if len(c.SiteSubnets) != 0 {
		t.Errorf("SiteSubnets = %v, want none (in-tunnel wide entry is an anomaly, not a subnet)", c.SiteSubnets)
	}
	if len(c.Anomalies) != 1 {
		t.Fatalf("Anomalies = %v, want exactly 1", c.Anomalies)
	}
}

func TestClassifyPeerRoutesBadTunnelCIDR(t *testing.T) {
	c := ClassifyPeerRoutes("not-a-cidr", []string{"10.10.0.5/32", "192.168.50.0/24"})
	if c.OwnAddress != "" || len(c.SiteSubnets) != 0 {
		t.Errorf("expected everything to fall into Anomalies, got %+v", c)
	}
	if len(c.Anomalies) != 2 {
		t.Fatalf("Anomalies = %v, want 2", c.Anomalies)
	}
}
