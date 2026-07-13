package xray

import "testing"

// TestParseRoundTrip builds a client link from each dialable strategy, parses
// it back, and confirms a relay outbound can be built -- the foreign-relay
// (#67) "paste the link" flow.
func TestParseRoundTrip(t *testing.T) {
	uuid, _ := NewUUID()
	kp, _ := GenRealityKeypair()
	cases := []struct {
		strategy string
		params   Params
		client   Client
		wantHost string // TLS strategies encode the cert domain as the link host
	}{
		{"reality-vless-tcp", Params{pPort: "443", pSNI: "www.microsoft.com", pDest: "www.microsoft.com:443", pRealityPriv: kp.PrivateKey, pRealityPub: kp.PublicKey, pShortID: "aabbccdd"}, Client{UUID: uuid}, "relay.abroad"},
		{"vless-vision-tls", Params{pPort: "443", pDomain: "vpn.example.com"}, Client{UUID: uuid}, "vpn.example.com"},
		{"vless-grpc-tls", Params{pPort: "443", pDomain: "vpn.example.com", pGRPCService: "gg"}, Client{UUID: uuid}, "vpn.example.com"},
		{"trojan-tcp-tls", Params{pPort: "443", pDomain: "vpn.example.com"}, Client{Password: "sekret"}, "vpn.example.com"},
		{"shadowsocks-2022", Params{pPort: "8388"}, Client{Password: "sekret"}, "relay.abroad"},
	}
	for _, c := range cases {
		s, _ := Get(c.strategy)
		link, err := s.ClientLink(c.params, c.client, "relay.abroad")
		if err != nil {
			t.Fatalf("%s ClientLink: %v", c.strategy, err)
		}
		spec, err := ParseClientLink(link)
		if err != nil {
			t.Fatalf("%s ParseClientLink(%q): %v", c.strategy, link, err)
		}
		if spec.Strategy != c.strategy {
			t.Errorf("%s parsed as %q", c.strategy, spec.Strategy)
		}
		if spec.Host != c.wantHost {
			t.Errorf("%s host = %q, want %q", c.strategy, spec.Host, c.wantHost)
		}
		if _, err := BuildRelayOutbound(spec); err != nil {
			t.Errorf("%s BuildRelayOutbound: %v", c.strategy, err)
		}
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	if _, err := ParseClientLink("https://example.com"); err == nil {
		t.Error("expected error for non-proxy link")
	}
}
