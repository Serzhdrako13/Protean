package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// FirewallPolicy is one server's INPUT-chain firewall settings. Baseline
// "never lock these out" ports are NOT part of this struct -- they're
// computed fresh at every apply from live DB/host state (see
// internal/firewall's renderer), never persisted here.
type FirewallPolicy struct {
	ServerID           string
	Enabled            bool
	DefaultIncoming    string // "drop" | "accept"
	RollbackWindowSecs int
	LastAppliedRuleset string
	LastAppliedAt      *time.Time
	LastConfirmedAt    *time.Time
	UpdatedAt          time.Time
}

// defaultFirewallPolicy is what a server with no row yet effectively has:
// disabled, drop-by-default once enabled, a 5-minute rollback window.
func defaultFirewallPolicy(serverID string) FirewallPolicy {
	return FirewallPolicy{ServerID: serverID, DefaultIncoming: "drop", RollbackWindowSecs: 300}
}

// GetFirewallPolicy returns serverID's policy, or sensible defaults (not an
// error) if it hasn't configured one yet -- "no row" is a normal state for
// a server that hasn't opted into this feature, not a failure.
func (s *Store) GetFirewallPolicy(ctx context.Context, serverID string) (FirewallPolicy, error) {
	var p FirewallPolicy
	err := s.pool.QueryRow(ctx, `
		SELECT server_id, enabled, default_incoming, rollback_window_secs,
		       last_applied_ruleset, last_applied_at, last_confirmed_at, updated_at
		FROM protean.firewall_policy WHERE server_id = $1
	`, serverID).Scan(&p.ServerID, &p.Enabled, &p.DefaultIncoming, &p.RollbackWindowSecs,
		&p.LastAppliedRuleset, &p.LastAppliedAt, &p.LastConfirmedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return defaultFirewallPolicy(serverID), nil
	}
	return p, err
}

// UpsertFirewallPolicy saves the admin-editable policy fields (enabled,
// default_incoming, rollback_window_secs) -- last_applied_*/last_confirmed_*
// are only ever set by SetLastApplied/SetLastConfirmed, reflecting an
// actual apply/confirm, never a plain settings edit.
func (s *Store) UpsertFirewallPolicy(ctx context.Context, p FirewallPolicy) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.firewall_policy (server_id, enabled, default_incoming, rollback_window_secs)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (server_id) DO UPDATE SET
			enabled = $2, default_incoming = $3, rollback_window_secs = $4, updated_at = now()
	`, p.ServerID, p.Enabled, p.DefaultIncoming, p.RollbackWindowSecs)
	return err
}

// SetLastApplied records a ruleset actually pushed to the host (armed
// rollback pending, not yet confirmed).
func (s *Store) SetLastApplied(ctx context.Context, serverID, ruleset string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.firewall_policy (server_id, last_applied_ruleset, last_applied_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (server_id) DO UPDATE SET
			last_applied_ruleset = $2, last_applied_at = $3, updated_at = now()
	`, serverID, ruleset, at)
	return err
}

// SetLastConfirmed records that firewall-confirm succeeded -- the ruleset
// in last_applied_ruleset is now the persisted, boot-surviving one.
func (s *Store) SetLastConfirmed(ctx context.Context, serverID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE protean.firewall_policy SET last_confirmed_at = $2, updated_at = now() WHERE server_id = $1
	`, serverID, at)
	return err
}

// FirewallRule is one of the admin's own custom INPUT rules, evaluated
// (in Ordering order) after the baseline/loopback/established rules the
// renderer always prepends.
type FirewallRule struct {
	ID         int64
	ServerID   string
	Ordering   int
	Action     string // accept|drop|reject
	Proto      string // tcp|udp|any
	PortSpec   string // "443", "8000:8100", "80,443" -- empty = any port
	SourceCIDR string // empty = anywhere
	Comment    string
	Enabled    bool
	CreatedAt  time.Time
}

func (s *Store) ListFirewallRules(ctx context.Context, serverID string) ([]FirewallRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, server_id, ordering, action, proto, port_spec, source_cidr, comment, enabled, created_at
		FROM protean.firewall_rules WHERE server_id = $1 ORDER BY ordering
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FirewallRule
	for rows.Next() {
		var r FirewallRule
		if err := rows.Scan(&r.ID, &r.ServerID, &r.Ordering, &r.Action, &r.Proto,
			&r.PortSpec, &r.SourceCIDR, &r.Comment, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReplaceFirewallRules atomically swaps serverID's entire custom rule set
// -- the draft-editing UI always sends the full set, not incremental
// add/remove, so a transactional delete+bulk-insert keeps this simple and
// leaves no orphaned rows on a partial failure.
func (s *Store) ReplaceFirewallRules(ctx context.Context, serverID string, rules []FirewallRule) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM protean.firewall_rules WHERE server_id = $1`, serverID); err != nil {
		return err
	}
	for _, r := range rules {
		if _, err := tx.Exec(ctx, `
			INSERT INTO protean.firewall_rules (server_id, ordering, action, proto, port_spec, source_cidr, comment, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, serverID, r.Ordering, r.Action, r.Proto, r.PortSpec, r.SourceCIDR, r.Comment, r.Enabled); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
