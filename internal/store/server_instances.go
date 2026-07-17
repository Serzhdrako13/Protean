package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ServerInstance is one VPN provider instance registered on one server —
// the DB-backed replacement for the old fixed env-var Template applied
// identically to every server (see internal/servers/manager.go).
type ServerInstance struct {
	ServerID  string
	LocalName string
	Type      string
	Config    map[string]string
	// Label is an admin-settable friendly name (e.g. "Германия") shown to
	// self-service portal users instead of the raw local_name -- empty
	// means "no friendly name set yet, fall back to the technical label."
	Label string
	// PortalVisible: explicit opt-in -- an instance is invisible to the
	// self-service portal (can't even be requested) until an admin flips
	// this on. Defaults false, including for auto-seeded legacy instances.
	PortalVisible bool
	// Description is an admin-settable freeform note (e.g. "домашняя сеть,
	// egress запрещён") shown to portal users alongside the label -- empty
	// means no note set.
	Description string
}

func (s *Store) ListServerInstances(ctx context.Context, serverID string) ([]ServerInstance, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT local_name, type, config, label, portal_visible, description FROM protean.server_instances
		WHERE server_id = $1
		ORDER BY type, local_name
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServerInstance
	for rows.Next() {
		var inst ServerInstance
		var cfgJSON string
		if err := rows.Scan(&inst.LocalName, &inst.Type, &cfgJSON, &inst.Label, &inst.PortalVisible, &inst.Description); err != nil {
			return nil, err
		}
		inst.ServerID = serverID
		inst.Config = map[string]string{}
		_ = json.Unmarshal([]byte(cfgJSON), &inst.Config) // malformed/empty -> empty map, not fatal
		out = append(out, inst)
	}
	return out, rows.Err()
}

// ListAllServerInstancePortalVisibility returns the set of instances (keyed
// "serverID:localName", same shape as registry ids) an admin has marked
// visible to the self-service portal. Absence from the map means false --
// mirrors ListAllServerInstanceLabels' "only non-default rows" shape.
func (s *Store) ListAllServerInstancePortalVisibility(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT server_id, local_name FROM protean.server_instances WHERE portal_visible = true
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var serverID, localName string
		if err := rows.Scan(&serverID, &localName); err != nil {
			return nil, err
		}
		out[serverID+":"+localName] = true
	}
	return out, rows.Err()
}

// UpdateServerInstanceVisibility flips whether an instance is visible to
// the self-service portal.
func (s *Store) UpdateServerInstanceVisibility(ctx context.Context, serverID, localName string, visible bool) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.server_instances SET portal_visible = $3 WHERE server_id = $1 AND local_name = $2
	`, serverID, localName, visible)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAllServerInstanceLabels returns every instance's friendly label across
// all servers, keyed by "serverID:localName" (the same shape as provider
// registry keys) -- for a single batch lookup instead of one query per
// provider when building labels for a list.
func (s *Store) ListAllServerInstanceLabels(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT server_id, local_name, label FROM protean.server_instances WHERE label != ''
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var serverID, localName, label string
		if err := rows.Scan(&serverID, &localName, &label); err != nil {
			return nil, err
		}
		out[serverID+":"+localName] = label
	}
	return out, rows.Err()
}

// UpdateServerInstanceLabel renames an existing instance's friendly label --
// the only way to label instances that were auto-seeded before this feature
// existed (they can't get a label at creation time since they predate it).
func (s *Store) UpdateServerInstanceLabel(ctx context.Context, serverID, localName, label string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.server_instances SET label = $3 WHERE server_id = $1 AND local_name = $2
	`, serverID, localName, label)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAllServerInstanceDescriptions mirrors ListAllServerInstanceLabels --
// every instance's admin note, keyed "serverID:localName", omitting empty ones.
func (s *Store) ListAllServerInstanceDescriptions(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT server_id, local_name, description FROM protean.server_instances WHERE description != ''
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var serverID, localName, description string
		if err := rows.Scan(&serverID, &localName, &description); err != nil {
			return nil, err
		}
		out[serverID+":"+localName] = description
	}
	return out, rows.Err()
}

// ListAllServerInstanceConfigChangedAt returns every instance's
// config_changed_at, keyed "serverID:localName" (same shape as registry
// ids) -- one batch query, for apiPortalMe's per-instance staleness check
// (see TouchServerInstanceConfig for what bumps this).
func (s *Store) ListAllServerInstanceConfigChangedAt(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT server_id, local_name, config_changed_at FROM protean.server_instances
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var serverID, localName string
		var changedAt time.Time
		if err := rows.Scan(&serverID, &localName, &changedAt); err != nil {
			return nil, err
		}
		out[serverID+":"+localName] = changedAt
	}
	return out, rows.Err()
}

// TouchServerInstanceConfig bumps config_changed_at to now -- called
// whenever an admin edits settings that land in a client's downloaded
// config (address/port/DNS/subnet/MTU), so the portal can flag existing
// downloads as stale until the user re-downloads.
func (s *Store) TouchServerInstanceConfig(ctx context.Context, serverID, localName string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE protean.server_instances SET config_changed_at = now() WHERE server_id = $1 AND local_name = $2
	`, serverID, localName)
	return err
}

// UpdateServerInstanceDescription sets an existing instance's admin note.
func (s *Store) UpdateServerInstanceDescription(ctx context.Context, serverID, localName, description string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.server_instances SET description = $3 WHERE server_id = $1 AND local_name = $2
	`, serverID, localName, description)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountServerInstancesByType reports how many instances of a type already
// exist on a server (used to cap single-instance types like ikev2/xray).
func (s *Store) CountServerInstancesByType(ctx context.Context, serverID, typ string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM protean.server_instances WHERE server_id = $1 AND type = $2
	`, serverID, typ).Scan(&n)
	return n, err
}

func (s *Store) CreateServerInstance(ctx context.Context, inst ServerInstance) error {
	if inst.Config == nil {
		inst.Config = map[string]string{}
	}
	cfgJSON, err := json.Marshal(inst.Config)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO protean.server_instances (server_id, local_name, type, config, label, portal_visible, description)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, inst.ServerID, inst.LocalName, inst.Type, string(cfgJSON), inst.Label, inst.PortalVisible, inst.Description)
	return err
}

// UpdateServerInstanceConfig merges patch into an existing instance's Config
// map (existing keys not present in patch are left as-is) -- config is a
// JSON-encoded TEXT column (see migration 0021), so this is a read-modify-
// write in Go rather than a jsonb merge in SQL. Used for settings an admin
// can change after creation (e.g. OpenVPN mtu/mssfix) where there's no
// per-field UPDATE like label/portal_visible have.
func (s *Store) UpdateServerInstanceConfig(ctx context.Context, serverID, localName string, patch map[string]string) error {
	var cfgJSON string
	err := s.pool.QueryRow(ctx, `
		SELECT config FROM protean.server_instances WHERE server_id = $1 AND local_name = $2
	`, serverID, localName).Scan(&cfgJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	cfg := map[string]string{}
	_ = json.Unmarshal([]byte(cfgJSON), &cfg)
	for k, v := range patch {
		cfg[k] = v
	}
	merged, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE protean.server_instances SET config = $3 WHERE server_id = $1 AND local_name = $2
	`, serverID, localName, string(merged))
	return err
}

func (s *Store) DeleteServerInstance(ctx context.Context, serverID, localName string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM protean.server_instances WHERE server_id = $1 AND local_name = $2
	`, serverID, localName)
	return err
}
