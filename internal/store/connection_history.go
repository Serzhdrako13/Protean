package store

import (
	"context"
	"time"
)

// ConnectionEvent is one persisted connect/disconnect transition.
type ConnectionEvent struct {
	TS       time.Time
	Provider string
	PeerID   string
	PeerName string
	Event    string // "connect" | "disconnect"
}

// InsertConnectionEvent records a connect/disconnect transition -- called
// from the same place internal/api/notify.go's watchTick already detects
// the transition for live notifications.
func (s *Store) InsertConnectionEvent(ctx context.Context, ts time.Time, provider, peerID, peerName, event string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.connection_history (ts, provider, peer_id, peer_name, event)
		VALUES ($1, $2, $3, $4, $5)
	`, ts, provider, peerID, peerName, event)
	return err
}

// ConnectionHistoryFilter narrows ListConnectionHistory -- empty fields are
// unfiltered.
type ConnectionHistoryFilter struct {
	Provider string
	PeerID   string
	Since    time.Time
	Limit    int
}

// ListConnectionHistory returns matching events, newest first.
func (s *Store) ListConnectionHistory(ctx context.Context, f ConnectionHistoryFilter) ([]ConnectionEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT ts, provider, peer_id, peer_name, event FROM wgpanel.connection_history
		WHERE ts >= $1
		  AND ($2 = '' OR provider = $2)
		  AND ($3 = '' OR peer_id = $3)
		ORDER BY ts DESC
		LIMIT $4
	`, f.Since, f.Provider, f.PeerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectionEvent
	for rows.Next() {
		var e ConnectionEvent
		if err := rows.Scan(&e.TS, &e.Provider, &e.PeerID, &e.PeerName, &e.Event); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneConnectionHistory deletes events older than the cutoff.
func (s *Store) PruneConnectionHistory(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM wgpanel.connection_history WHERE ts < $1`, before)
	return err
}
