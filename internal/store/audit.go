package store

import (
	"context"
	"time"
)

type AuditEntry struct {
	Timestamp time.Time
	Username  string
	Action    string
	Target    string
}

// AddAuditEntry records an admin action. Best-effort: callers log but don't
// fail the request if auditing itself fails.
func (s *Store) AddAuditEntry(ctx context.Context, username, action, target string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.audit_log (username, action, target) VALUES ($1, $2, $3)
	`, username, action, target)
	return err
}

func (s *Store) ListAuditEntries(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT ts, username, action, target
		FROM wgpanel.audit_log
		ORDER BY ts DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Timestamp, &e.Username, &e.Action, &e.Target); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
