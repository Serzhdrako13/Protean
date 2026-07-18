package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Server is a remote host the panel manages over SSH. EncKeyPEM is the
// AES-sealed SSH private key; callers decrypt it with the Encryptor.
type Server struct {
	ID         string
	Label      string
	Host       string
	Port       int
	SSHUser    string
	EncKeyPEM  []byte
	HostKey    string
	PublicHost string
	// Enabled: false stops the panel from connecting to this host / serving
	// its providers, but every server_instances row and provider-keyed
	// setting is left untouched -- distinct from deletion, which wipes them.
	Enabled bool
	// PanelHost: this row is the machine the panel itself runs on (may or
	// may not also be a VPN node) -- see 0039_panel_host.sql. At most one
	// row can have this set (partial unique index); set via
	// SetPanelHost/ClearPanelHost, never through Create/UpdateServer.
	PanelHost bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s *Store) CreateServer(ctx context.Context, srv Server) error {
	if srv.Port == 0 {
		srv.Port = 22
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.servers (id, label, host, port, ssh_user, enc_key_pem, host_key, public_host)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, srv.ID, srv.Label, srv.Host, srv.Port, srv.SSHUser, srv.EncKeyPEM, srv.HostKey, srv.PublicHost)
	return err
}

func (s *Store) UpdateServer(ctx context.Context, srv Server) error {
	if srv.Port == 0 {
		srv.Port = 22
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE protean.servers SET
			label = $2, host = $3, port = $4, ssh_user = $5,
			enc_key_pem = $6, host_key = $7, public_host = $8, updated_at = now()
		WHERE id = $1
	`, srv.ID, srv.Label, srv.Host, srv.Port, srv.SSHUser, srv.EncKeyPEM, srv.HostKey, srv.PublicHost)
	return err
}

func (s *Store) GetServer(ctx context.Context, id string) (Server, error) {
	var srv Server
	err := s.pool.QueryRow(ctx, `
		SELECT id, label, host, port, ssh_user, enc_key_pem, host_key, public_host, enabled, panel_host, created_at, updated_at
		FROM protean.servers WHERE id = $1
	`, id).Scan(&srv.ID, &srv.Label, &srv.Host, &srv.Port, &srv.SSHUser, &srv.EncKeyPEM,
		&srv.HostKey, &srv.PublicHost, &srv.Enabled, &srv.PanelHost, &srv.CreatedAt, &srv.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	return srv, err
}

func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, label, host, port, ssh_user, enc_key_pem, host_key, public_host, enabled, panel_host, created_at, updated_at
		FROM protean.servers ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.Label, &srv.Host, &srv.Port, &srv.SSHUser, &srv.EncKeyPEM,
			&srv.HostKey, &srv.PublicHost, &srv.Enabled, &srv.PanelHost, &srv.CreatedAt, &srv.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, rows.Err()
}

// GetPanelHost returns the servers row flagged as the panel's own host
// machine, or ErrNotFound if none is configured yet.
func (s *Store) GetPanelHost(ctx context.Context) (Server, error) {
	var srv Server
	err := s.pool.QueryRow(ctx, `
		SELECT id, label, host, port, ssh_user, enc_key_pem, host_key, public_host, enabled, panel_host, created_at, updated_at
		FROM protean.servers WHERE panel_host
	`).Scan(&srv.ID, &srv.Label, &srv.Host, &srv.Port, &srv.SSHUser, &srv.EncKeyPEM,
		&srv.HostKey, &srv.PublicHost, &srv.Enabled, &srv.PanelHost, &srv.CreatedAt, &srv.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	return srv, err
}

// SetPanelHost flags serverID as the panel's own host, clearing any
// previously-flagged row first (at most one panel host at a time -- the
// partial unique index on protean.servers also enforces this at the DB
// level, so a concurrent double-set fails loudly rather than silently).
func (s *Store) SetPanelHost(ctx context.Context, serverID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE protean.servers SET panel_host = false WHERE panel_host`); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE protean.servers SET panel_host = true WHERE id = $1`, serverID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// ClearPanelHost un-flags the panel host, if any is set. A no-op if none is.
func (s *Store) ClearPanelHost(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE protean.servers SET panel_host = false WHERE panel_host`)
	return err
}

// UpdateServerEnabled toggles a server's enabled flag.
func (s *Store) UpdateServerEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE protean.servers SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteServer(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.servers WHERE id = $1`, id)
	return err
}

// providerKeyedTables lists every table keyed by a bare "provider" column
// (the "<serverID>:<localName>" convention -- see 0017_server_scope.sql) with
// NO foreign key back to servers/server_instances, so nothing cascades on
// delete today. DeleteProviderData wipes all of them for one exact provider
// key -- used when fully deleting a server (backlog item 16) so provider
// settings/secrets/history don't linger as orphaned rows forever.
// Deliberately excludes `subnets`: that table is global site-subnet data
// (see 0003_subnets_global.sql), not per-instance settings.
var providerKeyedTables = []string{
	"peer_secrets", "disabled_peers", "provider_settings", "conf_backups",
	"ca_material", "openvpn_clients", "ikev2_clients", "peer_expiry",
	"notify_peer_mute", "peer_category", "revoked_certs", "crl_number",
	"cert_server_routes", "xray_instances", "xray_clients", "traffic_samples",
	"peer_owner", "access_request", "connection_history", "node_peer",
}

// DeleteProviderData wipes every provider-keyed row for one exact provider
// (e.g. "myserver:wg0") across all the tables in providerKeyedTables.
func (s *Store) DeleteProviderData(ctx context.Context, provider string) error {
	for _, table := range providerKeyedTables {
		if _, err := s.pool.Exec(ctx, `DELETE FROM protean.`+table+` WHERE provider = $1`, provider); err != nil {
			return fmt.Errorf("delete %s for %s: %w", table, provider, err)
		}
	}
	return nil
}

func (s *Store) CountServers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM protean.servers`).Scan(&n)
	return n, err
}
