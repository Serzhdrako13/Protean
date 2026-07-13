package api

import (
	"net/http"

	"protean/internal/notify"
)

type notifyField struct {
	Key    string
	Label  string
	Secret bool
}

// channelSpecs defines the config fields shown per channel kind.
var channelSpecs = []struct {
	Kind   string
	Label  string
	Fields []notifyField
}{
	{notify.KindTelegram, "Telegram", []notifyField{{"token", "Bot token", true}, {"chat_id", "Chat ID", false}}},
	{notify.KindMattermost, "Mattermost", []notifyField{{"url", "Incoming webhook URL", false}}},
	{notify.KindRocketChat, "Rocket.Chat", []notifyField{{"url", "Incoming webhook URL", false}}},
	{notify.KindVoceChat, "VoceChat", []notifyField{{"url", "Bot send URL", false}, {"api_key", "API key", true}}},
	{notify.KindXMPP, "XMPP", []notifyField{{"server", "Server host:port (optional)", false}, {"jid", "Bot JID", false}, {"password", "Password", true}, {"recipient", "Recipient JID", false}}},
	{notify.KindEmail, "Email (report)", []notifyField{{"host", "SMTP host:port", false}, {"user", "SMTP user", false}, {"pass", "SMTP password", true}, {"from", "From", false}, {"to", "To (comma-separated)", false}}},
}

func channelSpec(kind string) (struct {
	Kind   string
	Label  string
	Fields []notifyField
}, bool) {
	for _, s := range channelSpecs {
		if s.Kind == kind {
			return s, true
		}
	}
	return channelSpecs[0], false
}

func (s *Server) buildNotifyView(r *http.Request) notifyView {
	var view notifyView
	ctx := r.Context()

	for _, spec := range channelSpecs {
		cv := notifyChannelView{Kind: spec.Kind, Label: spec.Label}
		var cfg map[string]string
		if rec, err := s.store.GetNotifyChannel(ctx, spec.Kind); err == nil {
			cv.Enabled = rec.Enabled
			cfg, _ = s.decodeChannelConfig(rec.Config)
		}
		for _, f := range spec.Fields {
			fv := notifyFieldView{Key: f.Key, Label: f.Label, Secret: f.Secret}
			val := cfg[f.Key]
			if f.Secret {
				fv.Set = val != ""
			} else {
				fv.Value = val
			}
			cv.Fields = append(cv.Fields, fv)
		}
		view.Channels = append(view.Channels, cv)
	}

	if st, err := s.store.GetNotifySettings(ctx); err == nil {
		view.EvIfaceUpDown = st.EvIfaceUpDown
		view.EvSiteConnect = st.EvSiteConnect
		view.EvSiteDisconnect = st.EvSiteDisconnect
		view.EvClientConnect = st.EvClientConnect
		view.EvClientDisconnect = st.EvClientDisconnect
		view.EvUnknownPeer = st.EvUnknownPeer
		view.ReportEnabled = st.ReportEnabled
		view.ReportIntervalHours = st.ReportIntervalHours
		view.ReportIncludeEvents = st.ReportIncludeEvents
		view.ReportIncludeStatus = st.ReportIncludeStatus
		view.CtntProvider = st.CtntProvider
		view.CtntEndpoint = st.CtntEndpoint
		view.CtntAddress = st.CtntAddress
		view.CtntTime = st.CtntTime
	}
	if pending, err := s.store.ListNotifyPending(ctx); err == nil {
		view.PendingCount = len(pending)
	}
	return view
}
