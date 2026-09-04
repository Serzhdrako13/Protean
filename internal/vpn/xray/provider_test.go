package xray

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

type fakeSSH struct{ conf string }

func (f *fakeSSH) Run(context.Context, string) (string, error) { return "active", nil }
func (f *fakeSSH) ReadFile(context.Context, string) (string, error) {
	return f.conf, nil
}
func (f *fakeSSH) WriteFile(_ context.Context, _, content string) error {
	f.conf = content
	return nil
}

type fakeEnc struct{}

func (fakeEnc) Seal(s string) ([]byte, error) { return []byte(s), nil }
func (fakeEnc) Open(b []byte) (string, error) { return string(b), nil }

type fakeStore struct {
	strategy  string
	params    []byte
	relay     []byte
	hasInst   bool
	clients   map[string][]byte
	clientOrd []string
}

func newFakeStore() *fakeStore { return &fakeStore{clients: map[string][]byte{}} }

func (s *fakeStore) SaveInstance(_ context.Context, _, strategy string, encParams, encRelay []byte) error {
	s.strategy, s.params, s.relay, s.hasInst = strategy, encParams, encRelay, true
	return nil
}
func (s *fakeStore) GetInstance(context.Context, string) (string, []byte, []byte, error) {
	if !s.hasInst {
		return "", nil, nil, context.Canceled // any error
	}
	return s.strategy, s.params, s.relay, nil
}
func (s *fakeStore) SaveXrayClient(_ context.Context, _, name string, encCred []byte) error {
	if _, ok := s.clients[name]; !ok {
		s.clientOrd = append(s.clientOrd, name)
	}
	s.clients[name] = encCred
	return nil
}
func (s *fakeStore) ListXrayClients(context.Context, string) ([]ClientRow, error) {
	out := make([]ClientRow, 0, len(s.clientOrd))
	for _, n := range s.clientOrd {
		out = append(out, ClientRow{Name: n, EncCred: s.clients[n]})
	}
	return out, nil
}
func (s *fakeStore) DeleteXrayClient(_ context.Context, _, name string) error {
	delete(s.clients, name)
	for i, n := range s.clientOrd {
		if n == name {
			s.clientOrd = append(s.clientOrd[:i], s.clientOrd[i+1:]...)
			break
		}
	}
	return nil
}

func testProvider() (*Provider, *fakeSSH, *fakeStore) {
	ssh := &fakeSSH{}
	st := newFakeStore()
	p := New(Options{Instance: "hq:xray", PublicHost: "vpn.example.com", SSH: ssh, Store: st, Enc: fakeEnc{}})
	return p, ssh, st
}

func TestProviderApplyAutoClientAndLinks(t *testing.T) {
	p, ssh, _ := testProvider()
	ctx := context.Background()

	err := p.Apply(ctx, "reality-vless-tcp", Params{pSNI: "www.microsoft.com", pDest: "www.microsoft.com:443", pPort: "443"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(ssh.conf, "reality") {
		t.Errorf("host config not written with reality:\n%s", ssh.conf)
	}
	links, err := p.ClientLinks(ctx)
	if err != nil {
		t.Fatalf("ClientLinks: %v", err)
	}
	if len(links) != 1 || links[0].Name != "default" {
		t.Fatalf("expected 1 auto 'default' client, got %+v", links)
	}
	if !strings.HasPrefix(links[0].Link, "vless://") {
		t.Errorf("bad link %q", links[0].Link)
	}
}

func TestProviderMultiClientAndSubscription(t *testing.T) {
	p, _, _ := testProvider()
	ctx := context.Background()
	_ = p.Apply(ctx, "vless-vision-tls", Params{pDomain: "vpn.example.com", pPort: "443"}, nil)
	if err := p.AddClient(ctx, "alice"); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if err := p.AddClient(ctx, "bob"); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	links, _ := p.ClientLinks(ctx)
	if len(links) != 3 { // default + alice + bob
		t.Fatalf("want 3 clients, got %d", len(links))
	}
	sub, err := p.Subscription(ctx)
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	dec, err := base64.StdEncoding.DecodeString(sub)
	if err != nil {
		t.Fatalf("subscription not base64: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(dec)), "\n"); n != 2 { // 3 lines => 2 newlines between
		t.Errorf("subscription should hold 3 links, got %d newlines\n%s", n, dec)
	}

	if err := p.RemoveClient(ctx, "bob"); err != nil {
		t.Fatalf("RemoveClient: %v", err)
	}
	if links, _ := p.ClientLinks(ctx); len(links) != 2 {
		t.Errorf("after remove want 2, got %d", len(links))
	}
}

// TestInstanceSecretsPreservedAcrossReapply covers the generalized
// ensureInstanceCrypto path (formerly a hardcoded reality-vless-tcp name
// switch): re-applying the same strategy must keep its generated instance
// secrets (Reality keypair + short id) unchanged, not regenerate them --
// regenerating would invalidate every client link already handed out.
func TestInstanceSecretsPreservedAcrossReapply(t *testing.T) {
	p, _, _ := testProvider()
	ctx := context.Background()

	if err := p.Apply(ctx, "reality-vless-tcp", Params{pSNI: "www.microsoft.com", pDest: "www.microsoft.com:443", pPort: "443"}, nil); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	_, first, _, err := p.instance(ctx)
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	priv, pub, sid := first[pRealityPriv], first[pRealityPub], first[pShortID]
	if priv == "" || pub == "" || sid == "" {
		t.Fatalf("expected generated instance secrets, got %+v", first)
	}

	// Re-apply the same strategy with a changed operator param but no
	// secrets supplied -- the provider must carry the existing ones over.
	if err := p.Apply(ctx, "reality-vless-tcp", Params{pSNI: "www.microsoft.com", pDest: "www.microsoft.com:443", pPort: "8443"}, nil); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	_, second, _, err := p.instance(ctx)
	if err != nil {
		t.Fatalf("instance (2): %v", err)
	}
	if second[pRealityPriv] != priv || second[pRealityPub] != pub || second[pShortID] != sid {
		t.Errorf("instance secrets changed across re-apply: before=%+v after priv=%q pub=%q sid=%q",
			map[string]string{"priv": priv, "pub": pub, "sid": sid}, second[pRealityPriv], second[pRealityPub], second[pShortID])
	}
	if second[pPort] != "8443" {
		t.Errorf("port param = %q, want 8443 (should still update on re-apply)", second[pPort])
	}
}

func TestProviderSingleClientStrategyRejectsSecond(t *testing.T) {
	p, _, _ := testProvider()
	ctx := context.Background()
	_ = p.Apply(ctx, "shadowsocks-2022", Params{pPort: "8388"}, nil)
	if err := p.AddClient(ctx, "second"); err == nil {
		t.Error("shadowsocks-2022 should reject a second client")
	}
}

func TestProviderRelayFromLink(t *testing.T) {
	p, ssh, _ := testProvider()
	ctx := context.Background()
	relay, _ := ParseClientLink("trojan://sekret@relay.abroad:443?security=tls&sni=relay.abroad#r")
	if err := p.Apply(ctx, "vless-vision-tls", Params{pDomain: "hub.example.com", pPort: "443"}, &[]RelaySpec{relay}); err != nil {
		t.Fatalf("Apply with relay: %v", err)
	}
	if !strings.Contains(ssh.conf, "\"tag\": \"relay0\"") {
		t.Errorf("config missing relay outbound:\n%s", ssh.conf)
	}
}

func TestProviderRelayChainFromLinks(t *testing.T) {
	p, ssh, st := testProvider()
	ctx := context.Background()
	hop0, _ := ParseClientLink("trojan://sekret@relay0.abroad:443?security=tls&sni=relay0.abroad#r0")
	hop1, _ := ParseClientLink("ss://" + base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:pw1")) + "@relay1.abroad:8388#r1")
	if err := p.Apply(ctx, "vless-vision-tls", Params{pDomain: "hub.example.com", pPort: "443"}, &[]RelaySpec{hop0, hop1}); err != nil {
		t.Fatalf("Apply with relay chain: %v", err)
	}
	if !strings.Contains(ssh.conf, "\"tag\": \"relay0\"") || !strings.Contains(ssh.conf, "\"tag\": \"relay1\"") {
		t.Errorf("config missing chained relay outbounds:\n%s", ssh.conf)
	}
	if !strings.Contains(ssh.conf, "\"dialerProxy\": \"relay1\"") {
		t.Errorf("config missing dialerProxy chaining to relay1:\n%s", ssh.conf)
	}

	// Current() round-trips the ordered chain.
	_, _, relays, err := p.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(relays) != 2 || relays[0].Host != "relay0.abroad" || relays[1].Host != "relay1.abroad" {
		t.Errorf("Current relay chain = %+v", relays)
	}

	// The persisted blob is a JSON array, not a single object.
	if !strings.HasPrefix(strings.TrimSpace(string(st.relay)), "[") {
		t.Errorf("persisted relay blob should be a JSON array, got %s", st.relay)
	}
}

// TestProviderApplyPreservesRelayWhenNil is the regression test for the
// real bug: relay links are write-only (GET never returns them), so the
// admin's edit form always starts with blank hop inputs even when a
// chain is already configured. Before Apply distinguished "no relay
// argument sent" (nil) from "explicitly set to this" (non-nil), ANY
// params-only re-apply of the same strategy silently wiped an already-
// configured relay chain back to direct egress.
func TestProviderApplyPreservesRelayWhenNil(t *testing.T) {
	p, _, _ := testProvider()
	ctx := context.Background()
	hop, _ := ParseClientLink("trojan://sekret@relay.abroad:443?security=tls&sni=relay.abroad#r")

	if err := p.Apply(ctx, "vless-vision-tls", Params{pDomain: "hub.example.com", pPort: "443"}, &[]RelaySpec{hop}); err != nil {
		t.Fatalf("Apply with relay: %v", err)
	}

	// A routine params-only edit -- e.g. changing the port -- must not
	// touch the relay chain when relays is nil.
	if err := p.Apply(ctx, "vless-vision-tls", Params{pDomain: "hub.example.com", pPort: "8443"}, nil); err != nil {
		t.Fatalf("Apply without relay arg: %v", err)
	}
	_, _, relays, err := p.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(relays) != 1 || relays[0].Host != "relay.abroad" {
		t.Fatalf("relay chain should survive a nil-relays Apply, got %+v", relays)
	}

	// An explicit empty (but non-nil) slice IS the genuine "clear it" signal.
	if err := p.Apply(ctx, "vless-vision-tls", Params{pDomain: "hub.example.com", pPort: "8443"}, &[]RelaySpec{}); err != nil {
		t.Fatalf("Apply clearing relay: %v", err)
	}
	if _, _, relays, err := p.Current(ctx); err != nil || len(relays) != 0 {
		t.Fatalf("relay chain should be cleared by an explicit empty slice, got %+v (err %v)", relays, err)
	}

	// Switching strategy must never carry an old strategy's relay chain
	// forward, even with relays left nil -- a different strategy's hops
	// may not even be meaningful together.
	if err := p.Apply(ctx, "vless-vision-tls", Params{pDomain: "hub.example.com", pPort: "8443"}, &[]RelaySpec{hop}); err != nil {
		t.Fatalf("Apply with relay again: %v", err)
	}
	if err := p.Apply(ctx, "shadowsocks-2022", Params{pPort: "8388"}, nil); err != nil {
		t.Fatalf("Apply after switching strategy: %v", err)
	}
	if _, _, relays, err := p.Current(ctx); err != nil || len(relays) != 0 {
		t.Fatalf("relay chain should NOT carry over across a strategy switch, got %+v (err %v)", relays, err)
	}
}

func TestProviderDecodesLegacySingleRelayInstance(t *testing.T) {
	// Simulates a row saved before N-hop chaining shipped: encRelay held one
	// RelaySpec JSON object, not an array.
	p, _, st := testProvider()
	ctx := context.Background()
	st.strategy = "vless-vision-tls"
	st.params = []byte(`{}`)
	st.relay = []byte(`{"Strategy":"trojan-tcp-tls","Host":"legacy.abroad","Params":{"password":"pw"}}`)
	st.hasInst = true

	_, _, relays, err := p.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(relays) != 1 || relays[0].Host != "legacy.abroad" || relays[0].Strategy != "trojan-tcp-tls" {
		t.Errorf("legacy single-relay decode = %+v", relays)
	}
}
