package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// OwnedPeerKey identifies one peer assigned to a portal user.
type OwnedPeerKey struct {
	Provider string
	PeerKey  string
	// CreatedAt is when this peer was (last) granted/reassigned to the user.
	CreatedAt time.Time
	// DownloadedAt is when the user last downloaded/QR-scanned this peer's
	// config -- zero if they never have. See TouchPeerOwnerDownload.
	DownloadedAt time.Time
}

// SetPeerOwner assigns (or reassigns) a peer to a user.
func (s *Store) SetPeerOwner(ctx context.Context, provider, peerKey string, userID int64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.peer_owner (provider, peer_key, user_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, peer_key) DO UPDATE SET user_id = EXCLUDED.user_id, created_at = now()
	`, provider, peerKey, userID)
	return err
}

// ClearPeerOwner unassigns a peer (no-op if it had no owner).
func (s *Store) ClearPeerOwner(ctx context.Context, provider, peerKey string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM wgpanel.peer_owner WHERE provider = $1 AND peer_key = $2`, provider, peerKey)
	return err
}

// ListOwnedPeerKeys returns every peer assigned to a user, across all providers.
func (s *Store) ListOwnedPeerKeys(ctx context.Context, userID int64) ([]OwnedPeerKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, peer_key, created_at, config_downloaded_at FROM wgpanel.peer_owner WHERE user_id = $1 ORDER BY provider, peer_key
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OwnedPeerKey
	for rows.Next() {
		var k OwnedPeerKey
		var downloadedAt *time.Time
		if err := rows.Scan(&k.Provider, &k.PeerKey, &k.CreatedAt, &downloadedAt); err != nil {
			return nil, err
		}
		if downloadedAt != nil {
			k.DownloadedAt = *downloadedAt
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// TouchPeerOwnerDownload stamps config_downloaded_at to now -- called
// whenever a portal user actually downloads or QR-scans a peer's config,
// so apiPortalMe can tell whether they've picked up a later server-config
// change (see TouchServerInstanceConfig).
func (s *Store) TouchPeerOwnerDownload(ctx context.Context, provider, peerKey string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE wgpanel.peer_owner SET config_downloaded_at = now() WHERE provider = $1 AND peer_key = $2
	`, provider, peerKey)
	return err
}

// PeerOwnerRow is one peer's assignment, with the owner's username resolved
// -- for the admin peer table's "Владелец" column.
type PeerOwnerRow struct {
	PeerKey  string
	UserID   int64
	Username string
}

// ListOwnersForProvider returns every owned peer on one provider, joined
// with the owner's username, so the admin peer table can show current
// assignments without a lookup per row.
func (s *Store) ListOwnersForProvider(ctx context.Context, provider string) ([]PeerOwnerRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT po.peer_key, po.user_id, u.username
		FROM wgpanel.peer_owner po
		JOIN wgpanel.users u ON u.id = po.user_id
		WHERE po.provider = $1
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerOwnerRow
	for rows.Next() {
		var r PeerOwnerRow
		if err := rows.Scan(&r.PeerKey, &r.UserID, &r.Username); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GlobalPeerOwnerRow is one peer assignment anywhere in the system, with
// both the provider and the owner's username resolved -- for the admin
// "Портал" overview page, which needs to see every assigned peer across
// every server/instance (including ones hidden from the self-service
// portal), not just one provider's.
type GlobalPeerOwnerRow struct {
	Provider string
	PeerKey  string
	UserID   int64
	Username string
}

// ListAllOwnedPeers returns every owned peer in the system, joined with the
// owner's username.
func (s *Store) ListAllOwnedPeers(ctx context.Context) ([]GlobalPeerOwnerRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT po.provider, po.peer_key, po.user_id, u.username
		FROM wgpanel.peer_owner po
		JOIN wgpanel.users u ON u.id = po.user_id
		ORDER BY po.provider, u.username
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GlobalPeerOwnerRow
	for rows.Next() {
		var r GlobalPeerOwnerRow
		if err := rows.Scan(&r.Provider, &r.PeerKey, &r.UserID, &r.Username); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetPeerOwnerUserID returns the user id a peer is assigned to (ok=false if unassigned).
func (s *Store) GetPeerOwnerUserID(ctx context.Context, provider, peerKey string) (int64, bool, error) {
	var userID int64
	err := s.pool.QueryRow(ctx, `
		SELECT user_id FROM wgpanel.peer_owner WHERE provider = $1 AND peer_key = $2
	`, provider, peerKey).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return userID, true, nil
}
