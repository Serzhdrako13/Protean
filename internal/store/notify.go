package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotifyChannel is a stored channel config (config is AES-encrypted JSON).
type NotifyChannel struct {
	Kind    string
	Enabled bool
	Config  []byte
}

func (s *Store) SaveNotifyChannel(ctx context.Context, kind string, enabled bool, config []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.notify_channels (kind, enabled, config, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (kind) DO UPDATE SET enabled = EXCLUDED.enabled, config = EXCLUDED.config, updated_at = now()
	`, kind, enabled, config)
	return err
}

func (s *Store) GetNotifyChannel(ctx context.Context, kind string) (NotifyChannel, error) {
	var c NotifyChannel
	err := s.pool.QueryRow(ctx, `SELECT kind, enabled, config FROM protean.notify_channels WHERE kind = $1`, kind).
		Scan(&c.Kind, &c.Enabled, &c.Config)
	if errors.Is(err, pgx.ErrNoRows) {
		return NotifyChannel{}, ErrNotFound
	}
	return c, err
}

func (s *Store) ListNotifyChannels(ctx context.Context) ([]NotifyChannel, error) {
	rows, err := s.pool.Query(ctx, `SELECT kind, enabled, config FROM protean.notify_channels ORDER BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotifyChannel
	for rows.Next() {
		var c NotifyChannel
		if err := rows.Scan(&c.Kind, &c.Enabled, &c.Config); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NotifySettings is the singleton notification config.
type NotifySettings struct {
	EvIfaceUpDown       bool
	EvPeerOnOff         bool
	ReportEnabled       bool
	ReportIntervalHours int
	ReportIncludeEvents bool
	ReportIncludeStatus bool
	LastReportAt        time.Time
	// Content toggles: which fields to include in event messages.
	CtntProvider bool
	CtntEndpoint bool
	CtntAddress  bool
	CtntTime     bool
	// Per-category event selection + unknown-peer alert.
	EvSiteConnect      bool
	EvSiteDisconnect   bool
	EvClientConnect    bool
	EvClientDisconnect bool
	EvUnknownPeer      bool
}

func (s *Store) GetNotifySettings(ctx context.Context) (NotifySettings, error) {
	var n NotifySettings
	err := s.pool.QueryRow(ctx, `
		SELECT ev_iface_updown, ev_peer_onoff, report_enabled, report_interval_hours,
		       report_include_events, report_include_status, last_report_at,
		       ctnt_provider, ctnt_endpoint, ctnt_address, ctnt_time,
		       ev_site_connect, ev_site_disconnect, ev_client_connect, ev_client_disconnect, ev_unknown_peer
		FROM protean.notify_settings WHERE id = true
	`).Scan(&n.EvIfaceUpDown, &n.EvPeerOnOff, &n.ReportEnabled, &n.ReportIntervalHours,
		&n.ReportIncludeEvents, &n.ReportIncludeStatus, &n.LastReportAt,
		&n.CtntProvider, &n.CtntEndpoint, &n.CtntAddress, &n.CtntTime,
		&n.EvSiteConnect, &n.EvSiteDisconnect, &n.EvClientConnect, &n.EvClientDisconnect, &n.EvUnknownPeer)
	if errors.Is(err, pgx.ErrNoRows) {
		return NotifySettings{EvIfaceUpDown: true, ReportIntervalHours: 24, ReportIncludeEvents: true, ReportIncludeStatus: true, CtntProvider: true, CtntEndpoint: true, EvSiteDisconnect: true, EvClientConnect: true, EvUnknownPeer: true}, nil
	}
	return n, err
}

func (s *Store) SaveNotifySettings(ctx context.Context, n NotifySettings) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE protean.notify_settings SET
			ev_iface_updown = $1, ev_peer_onoff = $2, report_enabled = $3,
			report_interval_hours = $4, report_include_events = $5, report_include_status = $6,
			ctnt_provider = $7, ctnt_endpoint = $8, ctnt_address = $9, ctnt_time = $10,
			ev_site_connect = $11, ev_site_disconnect = $12, ev_client_connect = $13,
			ev_client_disconnect = $14, ev_unknown_peer = $15
		WHERE id = true
	`, n.EvIfaceUpDown, n.EvPeerOnOff, n.ReportEnabled, n.ReportIntervalHours,
		n.ReportIncludeEvents, n.ReportIncludeStatus,
		n.CtntProvider, n.CtntEndpoint, n.CtntAddress, n.CtntTime,
		n.EvSiteConnect, n.EvSiteDisconnect, n.EvClientConnect, n.EvClientDisconnect, n.EvUnknownPeer)
	return err
}

// PeerCategory returns a peer's category ("client" default) and whether a
// record exists.
func (s *Store) SetPeerCategory(ctx context.Context, provider, peerID, category string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.peer_category (provider, peer_id, category) VALUES ($1, $2, $3)
		ON CONFLICT (provider, peer_id) DO UPDATE SET category = EXCLUDED.category
	`, provider, peerID, category)
	return err
}

// PeerCategories returns peer_id -> category for a provider.
func (s *Store) PeerCategories(ctx context.Context, provider string) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT peer_id, category FROM protean.peer_category WHERE provider = $1`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, cat string
		if err := rows.Scan(&id, &cat); err != nil {
			return nil, err
		}
		out[id] = cat
	}
	return out, rows.Err()
}

func (s *Store) DeletePeerCategory(ctx context.Context, provider, peerID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.peer_category WHERE provider = $1 AND peer_id = $2`, provider, peerID)
	return err
}

// SetPeerMuted mutes/unmutes notifications for a specific peer.
func (s *Store) SetPeerMuted(ctx context.Context, provider, peerID string, muted bool) error {
	if muted {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO protean.notify_peer_mute (provider, peer_id) VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`, provider, peerID)
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.notify_peer_mute WHERE provider = $1 AND peer_id = $2`, provider, peerID)
	return err
}

// MutedPeers returns the set of muted peer ids for a provider.
func (s *Store) MutedPeers(ctx context.Context, provider string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT peer_id FROM protean.notify_peer_mute WHERE provider = $1`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *Store) MarkReportSent(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE protean.notify_settings SET last_report_at = now() WHERE id = true`)
	return err
}

// AddNotifyPending appends an event to the report accumulation buffer.
func (s *Store) AddNotifyPending(ctx context.Context, text string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO protean.notify_pending (text) VALUES ($1)`, text)
	return err
}

type PendingEvent struct {
	Timestamp time.Time
	Text      string
}

func (s *Store) ListNotifyPending(ctx context.Context) ([]PendingEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT ts, text FROM protean.notify_pending ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingEvent
	for rows.Next() {
		var e PendingEvent
		if err := rows.Scan(&e.Timestamp, &e.Text); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ClearNotifyPending(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.notify_pending`)
	return err
}
