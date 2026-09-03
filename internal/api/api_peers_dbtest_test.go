//go:build dbtest

// Integration tests against a real Postgres, mirroring
// internal/store/store_integration_test.go's harness. Bring the DB up
// first:
//
//	docker compose -f docker-compose.test.yml up -d
//	PROTEAN_TEST_DB='postgres://protean:protean@localhost:5433/protean?sslmode=disable' \
//	  go test -tags dbtest ./internal/api/
package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"protean/internal/auth"
	"protean/internal/store"
	"protean/internal/vpn"
)

// fakePubkey turns a short label into a 32-byte standard-base64 string
// (i.e. something that looks like a real WireGuard public key) so it
// round-trips through encodePeerID/decodePeerID the same way a real
// pubkey-keyed peer id would.
func fakePubkey(label string) string {
	b := make([]byte, 32)
	copy(b, label)
	return base64.StdEncoding.EncodeToString(b)
}

func mustEncodePeerID(t *testing.T, pubkey string) string {
	t.Helper()
	id, err := encodePeerID(pubkey)
	if err != nil {
		t.Fatalf("encodePeerID(%q): %v", pubkey, err)
	}
	return id
}

func peersTestDB(t *testing.T) *store.Store {
	t.Helper()
	url := os.Getenv("PROTEAN_TEST_DB")
	if url == "" {
		t.Skip("PROTEAN_TEST_DB not set; skipping DB integration tests")
	}
	ctx := context.Background()

	raw, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := raw.Exec(ctx, `DROP SCHEMA IF EXISTS protean CASCADE`); err != nil {
		raw.Close()
		t.Fatalf("drop schema: %v", err)
	}
	raw.Close()

	s, err := store.Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Migrate(ctx, s); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// updateTrackingProvider is a minimal in-memory wireguard-type
// vpn.Provider whose UpdatePeer actually mutates the tracked peer's
// AllowedIPs (unlike nodeFakeWGProvider's stub) -- needed to assert on
// what apiUpdatePeer actually computed and sent down.
type updateTrackingProvider struct {
	name  string
	peers []vpn.Peer
}

func (f *updateTrackingProvider) Name() string { return f.name }
func (f *updateTrackingProvider) Type() string { return "wireguard" }
func (f *updateTrackingProvider) Status(context.Context) (vpn.ServerStatus, error) {
	return vpn.ServerStatus{Provider: f.name, Up: true, PeerCount: len(f.peers)}, nil
}
func (f *updateTrackingProvider) ListPeers(context.Context) ([]vpn.Peer, error) { return f.peers, nil }
func (f *updateTrackingProvider) AddPeer(context.Context, vpn.PeerSpec) (vpn.NewPeerResult, error) {
	return vpn.NewPeerResult{}, vpn.ErrNotImplemented
}
func (f *updateTrackingProvider) UpdatePeer(_ context.Context, id string, spec vpn.PeerSpec) error {
	for i, p := range f.peers {
		if p.PublicKey == id {
			f.peers[i].Name = spec.Name
			f.peers[i].AllowedIPs = spec.AllowedIPs
			f.peers[i].PersistentKeepalive = spec.PersistentKeepalive
			return nil
		}
	}
	return vpn.ErrNotImplemented
}
func (f *updateTrackingProvider) RemovePeer(context.Context, string) error { return vpn.ErrNotImplemented }
func (f *updateTrackingProvider) UpdateServerConfig(context.Context, vpn.ServerConfig) error {
	return vpn.ErrNotImplemented
}

func newPeersTestServer(t *testing.T, st *store.Store, reg *vpn.Registry) *Server {
	t.Helper()
	enc, err := auth.NewEncryptor(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return &Server{reg: reg, store: st, enc: enc}
}

func doUpdatePeer(s *Server, provider, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/providers/"+provider+"/peers/"+id, strings.NewReader(body))
	req.SetPathValue("provider", provider)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.apiUpdatePeer(rec, req)
	return rec
}

// TestUpdatePeerPreservesSubnetRoutes is the regression test for the real
// bug found live on 2026-09-03: the peer edit modal has no subnet-
// selection UI at all, so req.SubnetIDs is always empty on every save.
// Before the fix, apiUpdatePeer rebuilt AllowedIPs purely from
// req.SubnetIDs, silently stripping any subnet CIDR a router peer already
// routed (adopted from an existing wg0.conf by Network structure
// detection) on every routine name/keepalive edit.
func TestUpdatePeerPreservesSubnetRoutes(t *testing.T) {
	st := peersTestDB(t)
	reg := vpn.NewRegistry()
	routerKey := fakePubkey("router")
	plainKey := fakePubkey("plain")
	prov := &updateTrackingProvider{
		name: "srv:wg0",
		peers: []vpn.Peer{
			{PublicKey: routerKey, Name: "router", AllowedIPs: []string{"192.168.99.25/32", "192.168.10.0/24", "192.168.15.0/24"}},
			{PublicKey: plainKey, Name: "plain-client", AllowedIPs: []string{"192.168.99.10/32"}},
		},
	}
	reg.Register(prov)
	s := newPeersTestServer(t, st, reg)
	routerID := mustEncodePeerID(t, routerKey)
	plainID := mustEncodePeerID(t, plainKey)

	// 1. A routine name-only edit (subnet_ids always [] from this form)
	// must preserve the router peer's existing subnet CIDRs verbatim.
	rec := doUpdatePeer(s, "srv:wg0", routerID,
		`{"name":"router-renamed","client_address":"192.168.99.25/32","keepalive":25,"subnet_ids":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update router: status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := prov.peers[0].AllowedIPs
	want := map[string]bool{"192.168.99.25/32": true, "192.168.10.0/24": true, "192.168.15.0/24": true}
	if len(got) != len(want) {
		t.Fatalf("router AllowedIPs after edit = %v, want exactly %v", got, want)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("unexpected AllowedIPs entry %q survived edit, full list: %v", ip, got)
		}
	}
	if prov.peers[0].Name != "router-renamed" {
		t.Errorf("name not updated: %q", prov.peers[0].Name)
	}

	// 2. A plain client peer with no extra subnet CIDRs must stay that way
	// after an edit -- no regression where preservation logic spuriously
	// invents entries for peers that never had any.
	rec = doUpdatePeer(s, "srv:wg0", plainID,
		`{"name":"plain-client","client_address":"192.168.99.10/32","keepalive":25,"subnet_ids":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update plain: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := prov.peers[1].AllowedIPs; len(got) != 1 || got[0] != "192.168.99.10/32" {
		t.Fatalf("plain client AllowedIPs after edit = %v, want just its own address", got)
	}

	// 3. Changing the peer's own address on edit must replace index 0,
	// not leave the old address lingering alongside the new one.
	rec = doUpdatePeer(s, "srv:wg0", routerID,
		`{"name":"router-renamed","client_address":"192.168.99.26/32","keepalive":25,"subnet_ids":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update router address: status=%d body=%s", rec.Code, rec.Body.String())
	}
	got = prov.peers[0].AllowedIPs
	for _, ip := range got {
		if ip == "192.168.99.25/32" {
			t.Errorf("old own-address should not survive an address change, got %v", got)
		}
	}
	if got[0] != "192.168.99.26/32" {
		t.Errorf("new own address should be index 0, got %v", got)
	}
}
