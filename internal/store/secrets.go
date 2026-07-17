package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// SavePeerSecret stores an already-encrypted private key blob for a peer
// the panel generated. Encryption happens in the caller (internal/auth or
// internal/vpn/clientconfig) -- this package only persists bytes.
func (s *Store) SavePeerSecret(ctx context.Context, provider, publicKey string, encryptedPrivateKey []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.peer_secrets (provider, public_key, encrypted_private_key)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, public_key) DO UPDATE SET encrypted_private_key = EXCLUDED.encrypted_private_key
	`, provider, publicKey, encryptedPrivateKey)
	return err
}

func (s *Store) GetPeerSecret(ctx context.Context, provider, publicKey string) ([]byte, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx, `
		SELECT encrypted_private_key FROM protean.peer_secrets
		WHERE provider = $1 AND public_key = $2
	`, provider, publicKey).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return blob, err
}

// ListPeerSecretKeys returns the public keys that have a stored secret for a
// provider, used by the startup reconcile to detect orphans.
func (s *Store) ListPeerSecretKeys(ctx context.Context, provider string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT public_key FROM protean.peer_secrets WHERE provider = $1
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var pk string
		if err := rows.Scan(&pk); err != nil {
			return nil, err
		}
		out = append(out, pk)
	}
	return out, rows.Err()
}

func (s *Store) DeletePeerSecret(ctx context.Context, provider, publicKey string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM protean.peer_secrets WHERE provider = $1 AND public_key = $2
	`, provider, publicKey)
	return err
}
