package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// OwnedNodePeerKey identifies one peer assigned to a node -- mirrors
// OwnedPeerKey (peer_owner.go), minus download-tracking (nodes never
// download a config themselves).
type OwnedNodePeerKey struct {
	Provider  string
	PeerKey   string
	CreatedAt time.Time
}

// SetNodePeer assigns (or reassigns) a peer to a node.
func (s *Store) SetNodePeer(ctx context.Context, provider, peerKey string, nodeID int64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.node_peer (provider, peer_key, node_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, peer_key) DO UPDATE SET node_id = EXCLUDED.node_id, created_at = now()
	`, provider, peerKey, nodeID)
	return err
}

// ClearNodePeer unassigns a peer (no-op if it had no node owner).
func (s *Store) ClearNodePeer(ctx context.Context, provider, peerKey string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM wgpanel.node_peer WHERE provider = $1 AND peer_key = $2`, provider, peerKey)
	return err
}

// ListNodeOwnedPeerKeys returns every peer assigned to a node, across all providers.
func (s *Store) ListNodeOwnedPeerKeys(ctx context.Context, nodeID int64) ([]OwnedNodePeerKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, peer_key, created_at FROM wgpanel.node_peer WHERE node_id = $1 ORDER BY provider, peer_key
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OwnedNodePeerKey
	for rows.Next() {
		var k OwnedNodePeerKey
		if err := rows.Scan(&k.Provider, &k.PeerKey, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetNodePeerOwnerID returns the node id a peer is assigned to (ok=false if unassigned).
func (s *Store) GetNodePeerOwnerID(ctx context.Context, provider, peerKey string) (int64, bool, error) {
	var nodeID int64
	err := s.pool.QueryRow(ctx, `
		SELECT node_id FROM wgpanel.node_peer WHERE provider = $1 AND peer_key = $2
	`, provider, peerKey).Scan(&nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return nodeID, true, nil
}

// NodePeerRow is one peer's node assignment, with the node's name resolved
// -- for the admin peer table's "Владелец" column (grouped alongside
// portal-user owners).
type NodePeerRow struct {
	PeerKey  string
	NodeID   int64
	NodeName string
}

// ListNodeOwnersForProvider returns every node-owned peer on one provider,
// joined with the owning node's name.
func (s *Store) ListNodeOwnersForProvider(ctx context.Context, provider string) ([]NodePeerRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT np.peer_key, np.node_id, n.name
		FROM wgpanel.node_peer np
		JOIN wgpanel.nodes n ON n.id = np.node_id
		WHERE np.provider = $1
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodePeerRow
	for rows.Next() {
		var r NodePeerRow
		if err := rows.Scan(&r.PeerKey, &r.NodeID, &r.NodeName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GlobalNodePeerRow is one node-owned peer anywhere in the system, with
// both the provider and the owning node's name resolved -- for the
// "Все клиенты" unified overview (mirrors GlobalPeerOwnerRow/
// ListAllOwnedPeers, peer_owner.go's equivalent for portal users).
type GlobalNodePeerRow struct {
	Provider string
	PeerKey  string
	NodeID   int64
	NodeName string
}

// ListAllNodeOwnedPeers returns every node-owned peer in the system,
// joined with the owning node's name.
func (s *Store) ListAllNodeOwnedPeers(ctx context.Context) ([]GlobalNodePeerRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT np.provider, np.peer_key, np.node_id, n.name
		FROM wgpanel.node_peer np
		JOIN wgpanel.nodes n ON n.id = np.node_id
		ORDER BY np.provider, n.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GlobalNodePeerRow
	for rows.Next() {
		var r GlobalNodePeerRow
		if err := rows.Scan(&r.Provider, &r.PeerKey, &r.NodeID, &r.NodeName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HasNetworkNodePeer reports whether some OTHER node with role
// "network_node" already owns a peer on this provider instance -- the
// safety invariant behind "1 network_node = 1 dedicated instance" (NAT/
// internet-egress is a per-instance setting; two independent network
// nodes sharing one instance would silently share that setting).
// excludeNodeID lets a node re-check against itself when re-granting
// (0 excludes nothing).
func (s *Store) HasNetworkNodePeer(ctx context.Context, provider string, excludeNodeID int64) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM wgpanel.node_peer np
			JOIN wgpanel.nodes n ON n.id = np.node_id
			WHERE np.provider = $1 AND n.role = 'network_node' AND np.node_id != $2
		)
	`, provider, excludeNodeID).Scan(&exists)
	return exists, err
}
