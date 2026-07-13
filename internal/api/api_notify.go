package api

import (
	"net/http"

	"protean/internal/notify"
)

type apiNotifySettings struct {
	EvIfaceUpDown       bool `json:"ev_iface_updown"`
	EvSiteConnect       bool `json:"ev_site_connect"`
	EvSiteDisconnect    bool `json:"ev_site_disconnect"`
	EvClientConnect     bool `json:"ev_client_connect"`
	EvClientDisconnect  bool `json:"ev_client_disconnect"`
	EvUnknownPeer       bool `json:"ev_unknown_peer"`
	ReportEnabled       bool `json:"report_enabled"`
	ReportIntervalHours int  `json:"report_interval_hours"`
	ReportIncludeEvents bool `json:"report_include_events"`
	ReportIncludeStatus bool `json:"report_include_status"`
	CtntProvider        bool `json:"ctnt_provider"`
	CtntEndpoint        bool `json:"ctnt_endpoint"`
	CtntAddress         bool `json:"ctnt_address"`
	CtntTime            bool `json:"ctnt_time"`
}

type apiNotify struct {
	// Channels/Fields are the existing template view structs
	// (notifyChannelView/notifyFieldView, types.go) reused as-is — no
	// PageHeader dependency, so they serialize fine (PascalCase keys).
	Channels     []notifyChannelView `json:"channels"`
	Settings     apiNotifySettings   `json:"settings"`
	PendingCount int                 `json:"pending_count"`
}

// GET /api/notifications
func (s *Server) apiNotifyGet(w http.ResponseWriter, r *http.Request) {
	v := s.buildNotifyView(r)
	writeOK(w, apiNotify{
		Channels: v.Channels,
		Settings: apiNotifySettings{
			EvIfaceUpDown: v.EvIfaceUpDown, EvSiteConnect: v.EvSiteConnect, EvSiteDisconnect: v.EvSiteDisconnect,
			EvClientConnect: v.EvClientConnect, EvClientDisconnect: v.EvClientDisconnect, EvUnknownPeer: v.EvUnknownPeer,
			ReportEnabled: v.ReportEnabled, ReportIntervalHours: v.ReportIntervalHours,
			ReportIncludeEvents: v.ReportIncludeEvents, ReportIncludeStatus: v.ReportIncludeStatus,
			CtntProvider: v.CtntProvider, CtntEndpoint: v.CtntEndpoint, CtntAddress: v.CtntAddress, CtntTime: v.CtntTime,
		},
		PendingCount: v.PendingCount,
	})
}

// POST /api/notifications/settings
func (s *Server) apiNotifySettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiNotifySettings
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	interval := req.ReportIntervalHours
	if interval < 1 {
		interval = 24
	}
	cur, _ := s.store.GetNotifySettings(r.Context())
	cur.EvIfaceUpDown = req.EvIfaceUpDown
	cur.EvSiteConnect = req.EvSiteConnect
	cur.EvSiteDisconnect = req.EvSiteDisconnect
	cur.EvClientConnect = req.EvClientConnect
	cur.EvClientDisconnect = req.EvClientDisconnect
	cur.EvUnknownPeer = req.EvUnknownPeer
	cur.ReportEnabled = req.ReportEnabled
	cur.ReportIntervalHours = interval
	cur.ReportIncludeEvents = req.ReportIncludeEvents
	cur.ReportIncludeStatus = req.ReportIncludeStatus
	cur.CtntProvider = req.CtntProvider
	cur.CtntEndpoint = req.CtntEndpoint
	cur.CtntAddress = req.CtntAddress
	cur.CtntTime = req.CtntTime
	if err := s.store.SaveNotifySettings(r.Context(), cur); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "notify.settings", "")
	writeOK(w, nil)
}

// POST /api/notifications/channel/{kind} — body is {field_key: value, ...,
// enabled: bool}; blank secret fields keep the previously stored value.
func (s *Server) apiNotifyChannelUpdate(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	spec, ok := channelSpec(kind)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown channel", "неизвестный канал"))
		return
	}
	var req map[string]any
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	cfg := map[string]string{}
	if rec, err := s.store.GetNotifyChannel(r.Context(), kind); err == nil {
		if old, err := s.decodeChannelConfig(rec.Config); err == nil {
			cfg = old
		}
	}
	for _, f := range spec.Fields {
		v, _ := req[f.Key].(string)
		if f.Secret && v == "" {
			continue // keep existing secret
		}
		cfg[f.Key] = v
	}
	enabled, _ := req["enabled"].(bool)

	blob, err := s.encodeChannelConfig(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SaveNotifyChannel(r.Context(), kind, enabled, blob); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "notify.channel", kind)
	writeOK(w, nil)
}

// POST /api/notifications/channel/{kind}/test
func (s *Server) apiNotifyChannelTest(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	ch := s.buildChannel(r.Context(), kind)
	if ch == nil {
		writeErr(w, http.StatusBadRequest, msg(r, "channel is not enabled/configured", "канал не включён или не настроен"))
		return
	}
	if err := ch.Send(r.Context(), notify.Message{Subject: "Control Panel VPN", Body: "Test notification"}); err != nil {
		writeErr(w, http.StatusBadGateway, msgf(r, "test failed: %v", "тест не выполнен: %v", err))
		return
	}
	writeOKMsg(w, msgf(r, "test sent via %s", "тест отправлен через %s", kind), nil)
}
