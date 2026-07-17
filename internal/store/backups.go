package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type ConfBackup struct {
	ID       int64
	Provider string
	SavedAt  time.Time
	Content  string
}

const confBackupsKeep = 20

// SaveConfBackup stores a snapshot of an interface config and prunes old
// snapshots to the most recent confBackupsKeep per provider.
func (s *Store) SaveConfBackup(ctx context.Context, provider, content string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO protean.conf_backups (provider, content) VALUES ($1, $2)
	`, provider, content); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		DELETE FROM protean.conf_backups
		WHERE provider = $1 AND id NOT IN (
			SELECT id FROM protean.conf_backups
			WHERE provider = $1 ORDER BY saved_at DESC LIMIT $2
		)
	`, provider, confBackupsKeep)
	return err
}

func (s *Store) GetConfBackup(ctx context.Context, id int64) (ConfBackup, error) {
	var b ConfBackup
	err := s.pool.QueryRow(ctx, `
		SELECT id, provider, saved_at, content FROM protean.conf_backups WHERE id = $1
	`, id).Scan(&b.ID, &b.Provider, &b.SavedAt, &b.Content)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConfBackup{}, ErrNotFound
	}
	return b, err
}

func (s *Store) ListConfBackups(ctx context.Context, provider string) ([]ConfBackup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, saved_at, content
		FROM protean.conf_backups
		WHERE provider = $1
		ORDER BY saved_at DESC
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ConfBackup
	for rows.Next() {
		var b ConfBackup
		if err := rows.Scan(&b.ID, &b.Provider, &b.SavedAt, &b.Content); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
