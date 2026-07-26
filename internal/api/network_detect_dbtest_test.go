//go:build dbtest

// Integration test against a real Postgres, reusing nodes_dbtest_test.go's
// harness (nodesTestDB/nodeFakeWGProvider/newNodesTestServer).
//
//	docker compose -f docker-compose.test.yml up -d
//	PROTEAN_TEST_DB='postgres://protean:protean@localhost:5433/protean?sslmode=disable' \
//	  go test -tags dbtest ./internal/api/
package api

import (
	"context"
	"testing"

	"protean/internal/vpn"
)

// TestNetworkDetectionEndToEnd exercises the whole detect -> apply flow
// against a mixed peer set matching a realistic adopted config: a plain
// client, a full-tunnel client, a router fronting a real site subnet, and
// an unnamed (conf-blind) peer with a routed subnet that can't become a
// Node. Then re-runs both detect and apply to confirm the second pass is
// a no-op, not a duplicate.
func TestNetworkDetectionEndToEnd(t *testing.T) {
	st := nodesTestDB(t)
	ctx := context.Background()
	reg := vpn.NewRegistry()
	prov := &nodeFakeWGProvider{name: "srv:wg0", address: "10.10.0.1/24", peers: []vpn.Peer{
		{Name: "phone", PublicKey: "pub-client", AllowedIPs: []string{"10.10.0.5/32"}},
		{Name: "laptop", PublicKey: "pub-fulltunnel", AllowedIPs: []string{"10.10.0.6/32", "0.0.0.0/0"}},
		{Name: "router1", PublicKey: "pub-router", AllowedIPs: []string{"10.10.0.9/32", "192.168.50.0/24"}},
		{Name: "", PublicKey: "pub-unnamed", AllowedIPs: []string{"10.10.0.7/32", "172.16.0.0/24"}},
	}}
	reg.Register(prov)
	s := newNodesTestServer(t, st, reg)

	items, tunnelCIDR, err := s.detectNetworkStructure(ctx, "srv:wg0")
	if err != nil {
		t.Fatalf("detectNetworkStructure: %v", err)
	}
	if tunnelCIDR != "10.10.0.0/24" {
		t.Fatalf("tunnelCIDR = %q", tunnelCIDR)
	}
	// Match items back to their PublicKey via decodePeerID for readable
	// assertions (PeerID in the response is the encoded urlID, not the
	// raw key).
	byPub := map[string]DetectedItem{}
	for _, it := range items {
		pub, err := decodePeerID(it.PeerID)
		if err != nil {
			t.Fatalf("decodePeerID(%q): %v", it.PeerID, err)
		}
		byPub[pub] = it
	}
	if len(byPub) != 4 {
		t.Fatalf("expected 4 items, got %d: %+v", len(byPub), items)
	}

	// DetectedItem.OwnAddress is the structural classifier's raw output
	// (mask kept -- it's used for exact-CIDR matching against Subnets,
	// not display); mask-stripped display formatting is a separate,
	// display-only concern (clientDisplayAddress / stripHostMask).
	client := byPub["pub-client"]
	if client.SuggestedAction != "none" || client.OwnAddress != "10.10.0.5/32" {
		t.Errorf("plain client = %+v", client)
	}
	fullTunnel := byPub["pub-fulltunnel"]
	if fullTunnel.SuggestedAction != "none" || !fullTunnel.FullTunnel || len(fullTunnel.RoutedSubnets) != 0 {
		t.Errorf("full-tunnel client = %+v", fullTunnel)
	}
	router := byPub["pub-router"]
	if router.SuggestedAction != "create_node" || router.OwnAddress != "10.10.0.9/32" ||
		len(router.RoutedSubnets) != 1 || router.RoutedSubnets[0] != "192.168.50.0/24" {
		t.Fatalf("router = %+v", router)
	}
	unnamed := byPub["pub-unnamed"]
	if unnamed.SuggestedAction != "anomaly" || len(unnamed.Anomalies) == 0 {
		t.Errorf("unnamed peer with a routed subnet should be an anomaly, not silently skipped: %+v", unnamed)
	}

	// Apply: create a Node for the router, catalogue its subnet; dismiss
	// the unnamed anomaly.
	decisions := []DetectionDecision{
		{
			PeerID: router.PeerID, Action: "create_node", NodeName: "router1", NodeKind: "router",
			SubnetsToCreate: []struct {
				CIDR  string `json:"cidr"`
				Label string `json:"label"`
			}{{CIDR: "192.168.50.0/24", Label: "router1 subnet"}},
		},
		{PeerID: unnamed.PeerID, Action: "skip"},
	}
	summary, err := s.applyNetworkDetection(ctx, "srv:wg0", decisions)
	if err != nil {
		t.Fatalf("applyNetworkDetection: %v", err)
	}
	if summary.NodesCreated != 1 || summary.SubnetsCreated != 1 || summary.Skipped != 1 {
		t.Fatalf("summary = %+v, want 1 node, 1 subnet, 1 skipped", summary)
	}

	nodeID, owned, err := st.GetNodePeerOwnerID(ctx, "srv:wg0", router.PeerID)
	if err != nil || !owned {
		t.Fatalf("router should be node-owned after apply: owned=%v err=%v", owned, err)
	}
	nodes, err := st.ListNodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].ID != nodeID || nodes[0].Role != "network_node" {
		t.Fatalf("ListNodes = %+v (id=%d) err=%v", nodes, nodeID, err)
	}
	cats, err := st.PeerCategories(ctx, "srv:wg0")
	if err != nil || cats["pub-router"] != "site" {
		t.Fatalf("PeerCategories = %+v err=%v, want pub-router=site", cats, err)
	}
	subnets, err := st.ListAllSubnets(ctx)
	if err != nil || len(subnets) != 1 || subnets[0].CIDR != "192.168.50.0/24" {
		t.Fatalf("ListAllSubnets = %+v err=%v", subnets, err)
	}
	dismissed, err := st.IsPeerDetectionDismissed(ctx, "srv:wg0", unnamed.PeerID)
	if err != nil || !dismissed {
		t.Fatalf("unnamed peer should be dismissed: dismissed=%v err=%v", dismissed, err)
	}

	// Re-run: detect must now report the router as already_handled (not
	// create_node again), and the unnamed anomaly as already_handled too
	// (dismissed). A second apply of the SAME decisions must not create a
	// second Node or a duplicate Subnet.
	items2, _, err := s.detectNetworkStructure(ctx, "srv:wg0")
	if err != nil {
		t.Fatalf("second detectNetworkStructure: %v", err)
	}
	for _, it := range items2 {
		pub, _ := decodePeerID(it.PeerID)
		if pub == "pub-router" && it.SuggestedAction != "already_handled" {
			t.Errorf("router on second detect = %+v, want already_handled", it)
		}
		if pub == "pub-unnamed" && it.SuggestedAction != "already_handled" {
			t.Errorf("unnamed on second detect = %+v, want already_handled (dismissed)", it)
		}
	}

	summary2, err := s.applyNetworkDetection(ctx, "srv:wg0", decisions)
	if err != nil {
		t.Fatalf("second applyNetworkDetection: %v", err)
	}
	if summary2.NodesCreated != 0 || summary2.SubnetsCreated != 0 || summary2.AlreadyHandled != 1 {
		t.Fatalf("second apply summary = %+v, want a no-op (0 new nodes/subnets, 1 already_handled)", summary2)
	}
	nodes2, err := st.ListNodes(ctx)
	if err != nil || len(nodes2) != 1 {
		t.Fatalf("ListNodes after second apply = %+v (want still exactly 1, no duplicate)", nodes2)
	}
	subnets2, err := st.ListAllSubnets(ctx)
	if err != nil || len(subnets2) != 1 {
		t.Fatalf("ListAllSubnets after second apply = %+v (want still exactly 1, no duplicate)", subnets2)
	}

	// A previously-dismissed anomaly (the unnamed peer) must still be
	// promotable to a Node once the admin supplies a name -- this is the
	// exact real-world bug: an unnamed router peer got dismissed by
	// mistake (a bare "skip" was the only action the old UI offered for
	// any anomaly row), and there was no way back in. undismiss clears
	// the decline, and a normal create_node decision then works exactly
	// like it would have for a named peer.
	summary3, err := s.applyNetworkDetection(ctx, "srv:wg0", []DetectionDecision{
		{PeerID: unnamed.PeerID, Action: "undismiss"},
	})
	if err != nil {
		t.Fatalf("undismiss: %v", err)
	}
	if summary3.Undismissed != 1 {
		t.Fatalf("summary3 = %+v, want 1 undismissed", summary3)
	}
	stillDismissed, err := st.IsPeerDetectionDismissed(ctx, "srv:wg0", unnamed.PeerID)
	if err != nil || stillDismissed {
		t.Fatalf("unnamed peer should no longer be dismissed: dismissed=%v err=%v", stillDismissed, err)
	}

	summary4, err := s.applyNetworkDetection(ctx, "srv:wg0", []DetectionDecision{
		{
			PeerID: unnamed.PeerID, Action: "create_node", NodeName: "shadow-router", NodeKind: "router",
			SubnetsToCreate: []struct {
				CIDR  string `json:"cidr"`
				Label string `json:"label"`
			}{{CIDR: "172.16.0.0/24", Label: "shadow-router subnet"}},
		},
	})
	if err != nil {
		t.Fatalf("create_node for the un-dismissed peer: %v", err)
	}
	if summary4.NodesCreated != 1 || summary4.SubnetsCreated != 1 {
		t.Fatalf("summary4 = %+v, want 1 node + 1 subnet created", summary4)
	}
	nodes3, err := st.ListNodes(ctx)
	if err != nil || len(nodes3) != 2 {
		t.Fatalf("ListNodes after promoting the un-dismissed peer = %+v, want 2 nodes total", nodes3)
	}
}
