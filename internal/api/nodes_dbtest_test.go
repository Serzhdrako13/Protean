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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"protean/internal/auth"
	"protean/internal/store"
	"protean/internal/vpn"
)

// nodesTestDB mirrors internal/store/store_integration_test.go's testDB
// helper (same reset-then-migrate approach), duplicated here since Go test
// helpers aren't exported across packages.
func nodesTestDB(t *testing.T) *store.Store {
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

// nodeFakeWGProvider is a minimal in-memory wireguard-type vpn.Provider
// that actually tracks added/removed peers (unlike mesh_test.go's
// meshFakeProvider, which never implements AddPeer) -- needed here since
// autoProvisionPeer/buildClientConfigText both round-trip through
// ListPeers to find the peer they just created.
type nodeFakeWGProvider struct {
	name    string
	address string
	peers   []vpn.Peer
	nextKey int
}

func (f *nodeFakeWGProvider) Name() string { return f.name }
func (f *nodeFakeWGProvider) Type() string { return "wireguard" }
func (f *nodeFakeWGProvider) Status(context.Context) (vpn.ServerStatus, error) {
	return vpn.ServerStatus{
		Provider: f.name, Up: true, Address: f.address,
		PublicKey: "server-pubkey", Endpoint: "203.0.113.1:51820",
		PeerCount: len(f.peers),
	}, nil
}
func (f *nodeFakeWGProvider) ListPeers(context.Context) ([]vpn.Peer, error) { return f.peers, nil }
func (f *nodeFakeWGProvider) AddPeer(_ context.Context, spec vpn.PeerSpec) (vpn.NewPeerResult, error) {
	f.nextKey++
	pub := "peer-pubkey-" + strconv.Itoa(f.nextKey)
	p := vpn.Peer{ID: pub, Provider: f.name, Name: spec.Name, PublicKey: pub, AllowedIPs: spec.AllowedIPs}
	f.peers = append(f.peers, p)
	return vpn.NewPeerResult{Peer: p, PrivateKey: "priv-" + pub}, nil
}
func (f *nodeFakeWGProvider) UpdatePeer(context.Context, string, vpn.PeerSpec) error {
	return vpn.ErrNotImplemented
}
func (f *nodeFakeWGProvider) RemovePeer(_ context.Context, pubkey string) error {
	out := f.peers[:0]
	for _, p := range f.peers {
		if p.PublicKey != pubkey {
			out = append(out, p)
		}
	}
	f.peers = out
	return nil
}
func (f *nodeFakeWGProvider) UpdateServerConfig(context.Context, vpn.ServerConfig) error {
	return vpn.ErrNotImplemented
}

func newNodesTestServer(t *testing.T, st *store.Store, reg *vpn.Registry) *Server {
	t.Helper()
	// auth.NewEncryptor wants a hex-encoded 32-byte (AES-256) key.
	enc, err := auth.NewEncryptor(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return &Server{reg: reg, store: st, enc: enc}
}

func doNodeAccessSet(s *Server, nodeID int64, provider string, enabled bool) *httptest.ResponseRecorder {
	body := `{"enabled":` + strconv.FormatBool(enabled) + `}`
	req := httptest.NewRequest(http.MethodPost, "/api/nodes/"+strconv.FormatInt(nodeID, 10)+"/access/"+provider, strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(nodeID, 10))
	req.SetPathValue("provider", provider)
	rec := httptest.NewRecorder()
	s.apiNodeAccessSet(rec, req)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) apiEnvelope {
	t.Helper()
	var env apiEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	return env
}

// TestNodeAccessGrantAutoProvision exercises the full grant path: a
// network_node-role node granted access to a wg-family instance gets a
// real peer auto-provisioned (NextFreeIP + AddPeer), ownership recorded in
// node_peer, and the post-creation sanity check (buildPeerDownload) must
// pass before the handler reports success.
func TestNodeAccessGrantAutoProvision(t *testing.T) {
	st := nodesTestDB(t)
	ctx := context.Background()
	reg := vpn.NewRegistry()
	prov := &nodeFakeWGProvider{name: "srv:wg0", address: "10.10.0.1/24"}
	reg.Register(prov)
	s := newNodesTestServer(t, st, reg)

	node, err := st.CreateNode(ctx, store.Node{Name: "Keenetic-Office", Kind: "router", Role: "network_node"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	rec := doNodeAccessSet(s, node.ID, "srv:wg0", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("grant: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if env := decodeEnvelope(t, rec); !env.Success {
		t.Fatalf("grant: success=false msg=%q", env.Msg)
	}
	if len(prov.peers) != 1 {
		t.Fatalf("provider should have 1 peer after grant, got %d", len(prov.peers))
	}
	owned, err := st.ListNodeOwnedPeerKeys(ctx, node.ID)
	if err != nil || len(owned) != 1 || owned[0].Provider != "srv:wg0" {
		t.Fatalf("ListNodeOwnedPeerKeys after grant: %+v err=%v", owned, err)
	}

	// Idempotent: granting again while already granted is a silent no-op,
	// not a second peer.
	rec2 := doNodeAccessSet(s, node.ID, "srv:wg0", true)
	if rec2.Code != http.StatusOK || len(prov.peers) != 1 {
		t.Fatalf("re-grant should be a no-op: code=%d peers=%d", rec2.Code, len(prov.peers))
	}

	// Revoke: real peer removed host-side + node_peer cleared.
	rec3 := doNodeAccessSet(s, node.ID, "srv:wg0", false)
	if rec3.Code != http.StatusOK {
		t.Fatalf("revoke: code=%d body=%s", rec3.Code, rec3.Body.String())
	}
	if len(prov.peers) != 0 {
		t.Fatalf("provider should have 0 peers after revoke, got %d", len(prov.peers))
	}
	if owned, _ := st.ListNodeOwnedPeerKeys(ctx, node.ID); len(owned) != 0 {
		t.Fatalf("node_peer should be empty after revoke, got %+v", owned)
	}
}

// TestNodeAccessNetworkNodeConflict is the safety-critical case: two
// different network_node-role nodes must never be able to share one
// provider instance, since internet-egress/NAT is a per-instance setting
// (see HasNetworkNodePeer) -- a second grant attempt must be rejected, not
// silently create a second peer that would share the first node's NAT
// configuration.
func doPeerSetNodeOwner(s *Server, provider, peerID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/providers/"+provider+"/peers/"+peerID+"/node-owner", strings.NewReader(body))
	req.SetPathValue("provider", provider)
	req.SetPathValue("id", peerID)
	rec := httptest.NewRecorder()
	s.apiPeerSetNodeOwner(rec, req)
	return rec
}

// TestPeerSetNodeOwnerCreatesNode is the regression test for a real
// support case: NodesPage's own standalone "add equipment" form had no
// field to link a peer at all, so a node created there needed a SEPARATE
// trip to a peer's Owner picker to actually mean anything -- an
// easy-to-miss second step that, when skipped, left the node created but
// completely unlinked (found live: a node existed in the DB with zero
// node_peer rows). apiPeerSetNodeOwner now creates the node itself when
// NodeID is 0 and a name is given, so the picker can do both in one call.
func TestPeerSetNodeOwnerCreatesNode(t *testing.T) {
	st := nodesTestDB(t)
	reg := vpn.NewRegistry()
	reg.Register(&nodeFakeWGProvider{name: "srv:wg0", address: "10.10.0.1/24"})
	s := newNodesTestServer(t, st, reg)
	ctx := context.Background()

	rec := doPeerSetNodeOwner(s, "srv:wg0", "b.somepeerkey", `{"node_id":0,"new_node_name":"Keenetic-New","new_node_kind":"router"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	nodes, err := st.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	var created *store.Node
	for i := range nodes {
		if nodes[i].Name == "Keenetic-New" {
			created = &nodes[i]
		}
	}
	if created == nil {
		t.Fatalf("expected a node named Keenetic-New to have been created, got: %+v", nodes)
	}
	if created.Kind != "router" {
		t.Errorf("kind = %q, want router", created.Kind)
	}
	if created.Role != "member" {
		t.Errorf("role = %q, want member (quick-create never picks network_node)", created.Role)
	}

	// The whole point: the peer must actually be linked, not just the
	// node existing in isolation.
	nodeID, ok, err := st.GetNodePeerOwnerID(ctx, "srv:wg0", "b.somepeerkey")
	if err != nil || !ok || nodeID != created.ID {
		t.Fatalf("GetNodePeerOwnerID after create-and-assign: id=%d ok=%v err=%v, want %d", nodeID, ok, err, created.ID)
	}
}

func TestNodeAccessNetworkNodeConflict(t *testing.T) {
	st := nodesTestDB(t)
	ctx := context.Background()
	reg := vpn.NewRegistry()
	prov := &nodeFakeWGProvider{name: "srv:wg0", address: "10.10.0.1/24"}
	reg.Register(prov)
	s := newNodesTestServer(t, st, reg)

	nodeA, err := st.CreateNode(ctx, store.Node{Name: "Site-A", Kind: "router", Role: "network_node"})
	if err != nil {
		t.Fatalf("CreateNode A: %v", err)
	}
	nodeB, err := st.CreateNode(ctx, store.Node{Name: "Site-B", Kind: "router", Role: "network_node"})
	if err != nil {
		t.Fatalf("CreateNode B: %v", err)
	}

	if rec := doNodeAccessSet(s, nodeA.ID, "srv:wg0", true); rec.Code != http.StatusOK {
		t.Fatalf("grant A: code=%d body=%s", rec.Code, rec.Body.String())
	}

	rec := doNodeAccessSet(s, nodeB.ID, "srv:wg0", true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("grant B onto A's instance should be rejected: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(prov.peers) != 1 {
		t.Fatalf("rejected grant must not create a peer: got %d peers", len(prov.peers))
	}

	// A member-role node, by contrast, is free to share the same instance
	// (no per-node NAT expectation for a plain peer).
	memberNode, err := st.CreateNode(ctx, store.Node{Name: "phone", Kind: "device", Role: "member"})
	if err != nil {
		t.Fatalf("CreateNode member: %v", err)
	}
	if rec := doNodeAccessSet(s, memberNode.ID, "srv:wg0", true); rec.Code != http.StatusOK {
		t.Fatalf("grant member onto shared instance should succeed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(prov.peers) != 2 {
		t.Fatalf("expected 2 peers after member grant, got %d", len(prov.peers))
	}
}
