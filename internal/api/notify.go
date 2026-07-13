package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"protean/internal/notify"
	"protean/internal/store"
)

// encodeChannelConfig / decodeChannelConfig store the per-channel config map
// as AES-encrypted JSON (tokens/passwords never sit in the DB in cleartext).
func (s *Server) encodeChannelConfig(cfg map[string]string) ([]byte, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return s.enc.Seal(string(raw))
}

func (s *Server) decodeChannelConfig(blob []byte) (map[string]string, error) {
	raw, err := s.enc.Open(blob)
	if err != nil {
		return nil, err
	}
	var cfg map[string]string
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// buildChannel constructs a live channel for a stored kind, or nil if it's
// disabled/misconfigured (logged).
func (s *Server) buildChannel(ctx context.Context, kind string) notify.Channel {
	rec, err := s.store.GetNotifyChannel(ctx, kind)
	if err != nil || !rec.Enabled {
		return nil
	}
	cfg, err := s.decodeChannelConfig(rec.Config)
	if err != nil {
		slog.Error("notify: decode channel config", "kind", kind, "err", err)
		return nil
	}
	ch, err := notify.New(kind, cfg)
	if err != nil {
		slog.Error("notify: build channel", "kind", kind, "err", err)
		return nil
	}
	return ch
}

// emit sends an event to all enabled instant channels (everything except
// email, which is report-only) and, when a report is enabled, buffers it.
func (s *Server) emit(ctx context.Context, text string) {
	for _, kind := range notify.AllKinds() {
		if kind == notify.KindEmail {
			continue
		}
		if ch := s.buildChannel(ctx, kind); ch != nil {
			if err := ch.Send(ctx, notify.Message{Subject: "Protean", Body: text}); err != nil {
				slog.Error("notify: send failed", "kind", kind, "err", err)
			}
		}
	}
	if settings, err := s.store.GetNotifySettings(ctx); err == nil && settings.ReportEnabled {
		if err := s.store.AddNotifyPending(ctx, text); err != nil {
			slog.Error("notify: buffer event", "err", err)
		}
	}
}

// --- event watcher ---

type peerMeta struct {
	name     string
	endpoint string
	address  string
	known    bool // has a panel record (named); false => added outside the panel
}

type ifaceSnapshot struct {
	up     bool
	online map[string]peerMeta // online peers -> meta (for message content)
}

// StartNotifyWatcher polls provider status and emits events on transitions.
func (s *Server) StartNotifyWatcher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	s.goWorker(func() {
		prev := map[string]ifaceSnapshot{}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.watchTick(ctx, prev)
			}
		}
	})
}

func (s *Server) watchTick(ctx context.Context, prev map[string]ifaceSnapshot) {
	settings, err := s.store.GetNotifySettings(ctx)
	if err != nil {
		return
	}
	for _, prov := range s.reg.List() {
		name := prov.Name()
		status, err := s.providerStatus(ctx, prov)
		if err != nil {
			continue
		}
		cur := ifaceSnapshot{up: status.Up, online: map[string]peerMeta{}}
		if status.Up {
			if peers, err := s.providerPeers(ctx, prov); err == nil {
				for _, p := range peers {
					if p.Online {
						// Key by public key (stable, matches the mute store);
						// the friendly name is carried for the message. A named
						// peer is panel-managed; an unnamed one was added
						// outside the panel ("foreign").
						cur.online[p.PublicKey] = peerMeta{name: p.Name, endpoint: p.Endpoint, address: peerOwnAddress(p), known: p.Name != ""}
					}
				}
			}
		}

		old, seen := prev[name]
		if seen {
			if settings.EvIfaceUpDown && old.up != cur.up {
				state := "DOWN"
				if cur.up {
					state = "UP"
				}
				s.emit(ctx, fmt.Sprintf("%s: interface is %s", name, state))
			}
			muted, _ := s.store.MutedPeers(ctx, name)
			cats, _ := s.store.PeerCategories(ctx, name)
			category := func(id string) string {
				if c := cats[id]; c != "" {
					return c
				}
				return "client"
			}
			// Connects. Persisted to connection_history unconditionally (a
			// muted/unnotified peer still really connected -- history is
			// independent of the notify settings gating live messages below).
			now := time.Now()
			for id, meta := range cur.online {
				if _, was := old.online[id]; was {
					continue
				}
				if err := s.store.InsertConnectionEvent(ctx, now, name, id, meta.name, "connect"); err != nil {
					slog.Error("connection history: insert connect", "provider", name, "err", err)
				}
				if muted[id] {
					continue
				}
				cat := category(id)
				if settings.EvUnknownPeer && !meta.known {
					s.emit(ctx, s.peerEventMsg(settings, name, id, "connected (UNKNOWN — not provisioned here)", cat, meta))
				} else if connectEnabled(settings, cat) {
					s.emit(ctx, s.peerEventMsg(settings, name, id, "connected", cat, meta))
				}
			}
			// Disconnects.
			for id, meta := range old.online {
				if _, still := cur.online[id]; still {
					continue
				}
				if err := s.store.InsertConnectionEvent(ctx, now, name, id, meta.name, "disconnect"); err != nil {
					slog.Error("connection history: insert disconnect", "provider", name, "err", err)
				}
				if muted[id] {
					continue
				}
				if disconnectEnabled(settings, category(id)) {
					s.emit(ctx, s.peerEventMsg(settings, name, id, "disconnected", category(id), meta))
				}
			}
		}
		prev[name] = cur
	}
}

// connectEnabled / disconnectEnabled select the per-category event flag.
func connectEnabled(s store.NotifySettings, category string) bool {
	if category == "site" {
		return s.EvSiteConnect
	}
	return s.EvClientConnect
}

func disconnectEnabled(s store.NotifySettings, category string) bool {
	if category == "site" {
		return s.EvSiteDisconnect
	}
	return s.EvClientDisconnect
}

// peerEventMsg builds a peer connect/disconnect message including only the
// fields enabled in the content settings.
func (s *Server) peerEventMsg(settings store.NotifySettings, provider, id, verb, category string, meta peerMeta) string {
	label := meta.name
	if label == "" {
		label = id
	}
	var b strings.Builder
	if settings.CtntProvider {
		b.WriteString(provider + ": ")
	}
	fmt.Fprintf(&b, "%s peer %q %s", category, label, verb)
	if settings.CtntAddress && meta.address != "" {
		fmt.Fprintf(&b, " [%s]", meta.address)
	}
	if settings.CtntEndpoint && meta.endpoint != "" {
		fmt.Fprintf(&b, " from %s", meta.endpoint)
	}
	if settings.CtntTime {
		fmt.Fprintf(&b, " at %s", time.Now().Format("15:04:05"))
	}
	return b.String()
}

// --- accumulating email report ---

// StartReportWorker periodically emails an accumulated report per the settings.
func (s *Server) StartReportWorker(ctx context.Context, checkEvery time.Duration) {
	if checkEvery <= 0 {
		checkEvery = 10 * time.Minute
	}
	s.goWorker(func() {
		t := time.NewTicker(checkEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.maybeSendReport(ctx)
			}
		}
	})
}

func (s *Server) maybeSendReport(ctx context.Context) {
	settings, err := s.store.GetNotifySettings(ctx)
	if err != nil || !settings.ReportEnabled {
		return
	}
	due := settings.LastReportAt.Add(time.Duration(settings.ReportIntervalHours) * time.Hour)
	if time.Now().Before(due) {
		return
	}
	email := s.buildChannel(ctx, notify.KindEmail)
	if email == nil {
		return // report enabled but email channel not configured
	}

	body := s.buildReportBody(ctx, settings)
	if err := email.Send(ctx, notify.Message{Subject: "Protean report", Body: body}); err != nil {
		slog.Error("notify: report send failed", "err", err)
		return // keep pending + last_report_at; retry next tick
	}
	_ = s.store.ClearNotifyPending(ctx)
	_ = s.store.MarkReportSent(ctx)
}

func (s *Server) buildReportBody(ctx context.Context, settings store.NotifySettings) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Protean report — %s\n\n", time.Now().Format("2006-01-02 15:04"))

	if settings.ReportIncludeStatus {
		b.WriteString("== Status ==\n")
		for _, prov := range s.reg.List() {
			st, err := s.providerStatus(ctx, prov)
			if err != nil {
				fmt.Fprintf(&b, "%s: error: %v\n", prov.Name(), err)
				continue
			}
			state := "down"
			if st.Up {
				state = "up"
			}
			fmt.Fprintf(&b, "%s (%s): %s, peers %d/%d online\n", prov.Name(), prov.Type(), state, st.PeersOnline, st.PeerCount)
		}
		b.WriteString("\n")
	}

	if settings.ReportIncludeEvents {
		b.WriteString("== Events since last report ==\n")
		pending, _ := s.store.ListNotifyPending(ctx)
		if len(pending) == 0 {
			b.WriteString("(none)\n")
		} else {
			for _, e := range pending {
				fmt.Fprintf(&b, "%s  %s\n", e.Timestamp.Format("2006-01-02 15:04:05"), e.Text)
			}
		}
	}
	return b.String()
}
