package store

import (
	"context"
	"time"
)

// TrafficSample is one rx/tx counter snapshot for a provider instance.
type TrafficSample struct {
	TS      time.Time
	RxBytes uint64
	TxBytes uint64
}

// InsertTrafficSample records a counter snapshot for the traffic history chart.
func (s *Store) InsertTrafficSample(ctx context.Context, provider string, ts time.Time, rx, tx uint64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.traffic_samples (provider, ts, rx_bytes, tx_bytes)
		VALUES ($1, $2, $3, $4)
	`, provider, ts, int64(rx), int64(tx))
	return err
}

// TrafficSamples returns a provider's counter snapshots since the given
// instant, oldest first.
func (s *Store) TrafficSamples(ctx context.Context, provider string, since time.Time) ([]TrafficSample, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, rx_bytes, tx_bytes FROM protean.traffic_samples
		WHERE provider = $1 AND ts >= $2
		ORDER BY ts ASC
	`, provider, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficSample
	for rows.Next() {
		var ts TrafficSample
		var rx, tx int64
		if err := rows.Scan(&ts.TS, &rx, &tx); err != nil {
			return nil, err
		}
		ts.RxBytes, ts.TxBytes = uint64(rx), uint64(tx)
		out = append(out, ts)
	}
	return out, rows.Err()
}

// AggregateTrafficSamples sums rx/tx across every provider instance sampled
// at the same instant (the sampler writes all providers in one tick with a
// shared timestamp — see api.sampleTraffic — so grouping by ts exactly lines
// up rounds instead of needing time-bucket approximation), oldest first.
func (s *Store) AggregateTrafficSamples(ctx context.Context, since time.Time) ([]TrafficSample, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, SUM(rx_bytes), SUM(tx_bytes) FROM protean.traffic_samples
		WHERE ts >= $1
		GROUP BY ts
		ORDER BY ts ASC
	`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficSample
	for rows.Next() {
		var ts TrafficSample
		var rx, tx int64
		if err := rows.Scan(&ts.TS, &rx, &tx); err != nil {
			return nil, err
		}
		ts.RxBytes, ts.TxBytes = uint64(rx), uint64(tx)
		out = append(out, ts)
	}
	return out, rows.Err()
}

// AggregateTrafficSamplesByServer sums rx/tx across every provider instance
// on one server (provider keys are always "serverID:localName" -- see the
// registry convention), same grouping-by-exact-ts approach as
// AggregateTrafficSamples. Backs the Index page's per-server traffic chart.
func (s *Store) AggregateTrafficSamplesByServer(ctx context.Context, serverID string, since time.Time) ([]TrafficSample, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, SUM(rx_bytes), SUM(tx_bytes) FROM protean.traffic_samples
		WHERE split_part(provider, ':', 1) = $1 AND ts >= $2
		GROUP BY ts
		ORDER BY ts ASC
	`, serverID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficSample
	for rows.Next() {
		var ts TrafficSample
		var rx, tx int64
		if err := rows.Scan(&ts.TS, &rx, &tx); err != nil {
			return nil, err
		}
		ts.RxBytes, ts.TxBytes = uint64(rx), uint64(tx)
		out = append(out, ts)
	}
	return out, rows.Err()
}

// PruneTrafficSamples deletes samples older than the cutoff (retention window).
func (s *Store) PruneTrafficSamples(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.traffic_samples WHERE ts < $1`, before)
	return err
}
