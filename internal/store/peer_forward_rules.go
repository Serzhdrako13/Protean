package store

import "context"

// SetPeerForwardRules replaces the full destination list for one peer
// (full-replace/sync, matching how the UI presents "the current list" --
// not an incremental add/del event stream). Passing an empty/nil list
// clears all rules for the peer (back to fully unrestricted). Purely a DB
// write -- the API layer is responsible for pushing/tearing down the live
// iptables rules via Installer.SetPeerForwardRules.
func (s *Store) SetPeerForwardRules(ctx context.Context, provider, peerKey string, destinations []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx, `
		DELETE FROM protean.peer_forward_rules WHERE provider = $1 AND peer_key = $2
	`, provider, peerKey); err != nil {
		return err
	}
	for _, d := range destinations {
		if _, err := tx.Exec(ctx, `
			INSERT INTO protean.peer_forward_rules (provider, peer_key, destination)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING
		`, provider, peerKey, d); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ListPeerForwardRules returns one peer's current destination allowlist
// (empty/nil means unrestricted).
func (s *Store) ListPeerForwardRules(ctx context.Context, provider, peerKey string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT destination FROM protean.peer_forward_rules
		WHERE provider = $1 AND peer_key = $2
		ORDER BY destination
	`, provider, peerKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PeerForwardRuleGroup is one peer's full destination list -- for reboot
// replay (mirrors ListAllSubnets' bulk-list role behind ReapplySubnetNAT).
type PeerForwardRuleGroup struct {
	Provider     string
	PeerKey      string
	Destinations []string
}

// ListAllPeerForwardRules returns every peer that has at least one rule,
// grouped by (provider, peer_key), in one query.
func (s *Store) ListAllPeerForwardRules(ctx context.Context) ([]PeerForwardRuleGroup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, peer_key, array_agg(destination ORDER BY destination)
		FROM protean.peer_forward_rules
		GROUP BY provider, peer_key
		ORDER BY provider, peer_key
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerForwardRuleGroup
	for rows.Next() {
		var g PeerForwardRuleGroup
		if err := rows.Scan(&g.Provider, &g.PeerKey, &g.Destinations); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeletePeerForwardRules removes all rules for one peer -- must be called
// when a peer is deleted (peer_key isn't FK-backed here the way node_id
// is, so this needs an explicit call, not a cascade). Without this, a
// deleted-then-recreated peer that gets the same tunnel address (address
// reuse) would silently inherit a stale restriction.
func (s *Store) DeletePeerForwardRules(ctx context.Context, provider, peerKey string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM protean.peer_forward_rules WHERE provider = $1 AND peer_key = $2
	`, provider, peerKey)
	return err
}
