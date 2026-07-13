package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"protean/internal/store"
)

// apiPortalInstance is one provider instance as shown to a portal user —
// every registered instance appears (skip only Xray, a structurally
// different shape with no peer id), in exactly one of 4 states:
// "none" (no request yet), "pending" (requested, or admin approved but no
// confirmed-working peer yet — that distinction is admin-side only, see
// api_access_requests.go), "denied", or "granted" (real peer, usable now).
type apiPortalInstance struct {
	Provider      string `json:"provider"`
	ProviderLabel string `json:"provider_label"`
	// ProviderType is the raw protocol ("wireguard"/"amneziawg"/"openvpn"/
	// "ikev2") -- lets the portal show which VPN app/setup instructions
	// apply, without exposing the technical instance name.
	ProviderType string `json:"provider_type"`
	// Description is the admin-set note for this instance, if any (e.g.
	// "домашняя сеть, egress запрещён").
	Description string `json:"description,omitempty"`
	State       string `json:"state"`
	// Set only when State == "granted".
	PeerKey       string    `json:"peer_key,omitempty"`
	Name          string    `json:"name,omitempty"`
	Online        bool      `json:"online,omitempty"`
	RxBytes       uint64    `json:"rx_bytes,omitempty"`
	TxBytes       uint64    `json:"tx_bytes,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	// ConfigStale: the admin changed this instance's server-config (address/
	// port/DNS/subnet/MTU) after the user last downloaded their config --
	// prompts a "re-download" banner. Only meaningful when granted.
	ConfigStale bool `json:"config_stale,omitempty"`
}

type apiPortalMeView struct {
	Username        string              `json:"username"`
	PasswordExpired bool                `json:"password_expired"`
	TOTPEnabled     bool                `json:"totp_enabled"`
	Language        string              `json:"language,omitempty"`
	Instances       []apiPortalInstance `json:"instances"`
}

// GET /api/portal/password-policy — read-only mirror of
// /api/password-policy/settings, reachable by role=="user" sessions (which
// requireAuthAPI otherwise confines to portalRoleAllowedPrefixes) so the
// portal's change-password form can show/enforce the real rules instead of
// a hardcoded "min 8 chars" guess that silently drifts from whatever an
// admin actually configured.
func (s *Server) apiPortalPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetPasswordPolicySettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiPasswordPolicySettings(t))
}

// GET /api/portal/me — the self-service portal's device/instance list.
func (s *Server) apiPortalMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := s.store.GetUserByID(ctx, userIDFromContext(ctx))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	owned, err := s.store.ListOwnedPeerKeys(ctx, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ownedByProvider := map[string]store.OwnedPeerKey{}
	for _, o := range owned {
		ownedByProvider[o.Provider] = o
	}
	configChangedAt := s.instanceConfigChangedAt(ctx)

	requests, err := s.store.ListRequestsForUser(ctx, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	reqByProvider := map[string]store.AccessRequest{}
	for _, req := range requests {
		reqByProvider[req.Provider] = req
	}

	labels := s.instanceLabels(ctx)
	visible := s.instancePortalVisibility(ctx)
	descriptions := s.instanceDescriptions(ctx)
	totpEnabled, _ := s.auth.TOTPEnabled(ctx, u.ID)
	view := apiPortalMeView{
		Username: u.Username, PasswordExpired: s.isPasswordExpired(ctx, u.PasswordChangedAt), TOTPEnabled: totpEnabled,
		Language: u.Language,
	}
	for _, prov := range s.reg.List() {
		if prov.Type() == "xray" {
			continue
		}
		name := prov.Name()
		_, owns := ownedByProvider[name]
		_, hasRequest := reqByProvider[name]
		if !owns && !hasRequest && !visible[name] {
			// Not opted in for the portal, and this user has no existing
			// relationship with it (owned peer or a past request) worth
			// preserving -- don't even list it as requestable.
			continue
		}
		inst := apiPortalInstance{
			Provider: name, ProviderLabel: s.providerLabel(name, labels),
			ProviderType: prov.Type(), Description: descriptions[name],
		}

		if own, ok := ownedByProvider[name]; ok {
			inst.State = "granted"
			inst.PeerKey = own.PeerKey
			if pubkey, err := decodePeerID(own.PeerKey); err == nil {
				if peer, err := s.findPeer(ctx, prov, pubkey); err == nil {
					inst.Name = peer.Name
					inst.Online = peer.Online
					inst.RxBytes = peer.RxBytes
					inst.TxBytes = peer.TxBytes
					inst.LastHandshake = peer.LastHandshake
				} else {
					slog.Warn("portal: owned peer not found on provider", "provider", name, "peer_key", own.PeerKey, "err", err)
				}
			}
			lastSeen := own.DownloadedAt
			if lastSeen.IsZero() {
				lastSeen = own.CreatedAt
			}
			inst.ConfigStale = configChangedAt[name].After(lastSeen)
			view.Instances = append(view.Instances, inst)
			continue
		}

		if req, ok := reqByProvider[name]; ok && req.Status != "" {
			switch req.Status {
			case "denied":
				inst.State = "denied"
			default: // pending, approved
				inst.State = "pending"
			}
			view.Instances = append(view.Instances, inst)
			continue
		}

		inst.State = "none"
		view.Instances = append(view.Instances, inst)
	}
	writeOK(w, view)
}

// portalOwnsPeer reports whether the calling portal user owns this peer.
func (s *Server) portalOwnsPeer(ctx context.Context, provider, peerKey string) bool {
	u, err := s.store.GetUserByID(ctx, userIDFromContext(ctx))
	if err != nil {
		return false
	}
	ownerID, ok, err := s.store.GetPeerOwnerUserID(ctx, provider, peerKey)
	if err != nil || !ok {
		return false
	}
	return ownerID == u.ID
}

// GET /api/portal/peers/{provider}/{key}/config — ownership-checked twin of
// the admin peer-download route, sharing the same buildPeerDownload core.
func (s *Server) apiPortalPeerConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	provider := r.PathValue("provider")
	key := r.PathValue("key")
	if !s.portalOwnsPeer(ctx, provider, key) {
		http.Error(w, msg(r, "not your device", "это не ваше устройство"), http.StatusForbidden)
		return
	}
	pubkey, err := decodePeerID(key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	format := r.URL.Query().Get("format")
	s.audit(ctx, "portal.peer.config.download", provider+"/"+key)
	contentType, filename, data, err := s.buildPeerDownload(ctx, provider, pubkey, format)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNoAltProfile) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	if err := s.store.TouchPeerOwnerDownload(ctx, provider, key); err != nil {
		slog.Warn("touch peer_owner config_downloaded_at failed", "provider", provider, "key", key, "err", err)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write(data)
}

// GET /api/portal/peers/{provider}/{key}/config/text — ownership-checked
// twin of apiPeerConfigText, for a user's own device (some client apps
// can't import a file, but the fields can be typed in by hand).
func (s *Server) apiPortalPeerConfigText(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	provider := r.PathValue("provider")
	key := r.PathValue("key")
	if !s.portalOwnsPeer(ctx, provider, key) {
		http.Error(w, msg(r, "not your device", "это не ваше устройство"), http.StatusForbidden)
		return
	}
	pubkey, err := decodePeerID(key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.audit(ctx, "portal.peer.config.manual_view", provider+"/"+key)
	text, err := s.buildPeerConfigText(ctx, provider, pubkey)
	if err != nil {
		if errors.Is(err, errNoManualSetup) {
			writeErr(w, http.StatusBadRequest, msg(r, "manual setup isn't available for this provider type", "ручная настройка недоступна для этого типа провайдера"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.TouchPeerOwnerDownload(ctx, provider, key); err != nil {
		slog.Warn("touch peer_owner config_downloaded_at failed", "provider", provider, "key", key, "err", err)
	}
	writeOK(w, map[string]string{"text": text})
}

// GET /api/portal/peers/{provider}/{key}/qr
func (s *Server) apiPortalPeerQR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	provider := r.PathValue("provider")
	key := r.PathValue("key")
	if !s.portalOwnsPeer(ctx, provider, key) {
		http.Error(w, msg(r, "not your device", "это не ваше устройство"), http.StatusForbidden)
		return
	}
	pubkey, err := decodePeerID(key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.audit(ctx, "portal.peer.config.qr", provider+"/"+key)
	png, err := s.buildPeerQRPNG(ctx, provider, pubkey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.TouchPeerOwnerDownload(ctx, provider, key); err != nil {
		slog.Warn("touch peer_owner config_downloaded_at failed", "provider", provider, "key", key, "err", err)
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

type apiPortalConnectionEvent struct {
	TS            time.Time `json:"ts"`
	ProviderLabel string    `json:"provider_label"`
	DeviceName    string    `json:"device_name"`
	Event         string    `json:"event"`
}

// GET /api/portal/connection-history?since_hours=&limit= — connect/disconnect
// history for the CALLING user's own devices only (never accepts a provider/
// peer_id from the client, unlike the admin GET /api/connection-history --
// scoping is derived entirely from peer_owner, so a portal user can't probe
// another user's device history by guessing IDs). connection_history rows
// key peer_id by the raw public key (see notify.go's watchTick), while
// peer_owner.peer_key is the URL-safe encoded id (see encodePeerID) -- so
// each owned key is decoded back to a raw pubkey before filtering.
func (s *Server) apiPortalConnectionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := s.store.GetUserByID(ctx, userIDFromContext(ctx))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	owned, err := s.store.ListOwnedPeerKeys(ctx, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	q := r.URL.Query()
	sinceHours, _ := strconv.Atoi(q.Get("since_hours"))
	if sinceHours <= 0 {
		sinceHours = 24 * 7
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	since := time.Now().Add(-time.Duration(sinceHours) * time.Hour)

	labels := s.instanceLabels(ctx)
	all := make([]apiPortalConnectionEvent, 0)
	for _, ownedKey := range owned {
		pubkey, err := decodePeerID(ownedKey.PeerKey)
		if err != nil {
			continue
		}
		rows, err := s.store.ListConnectionHistory(ctx, store.ConnectionHistoryFilter{
			Provider: ownedKey.Provider, PeerID: pubkey, Since: since, Limit: limit,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		label := s.providerLabel(ownedKey.Provider, labels)
		for _, row := range rows {
			all = append(all, apiPortalConnectionEvent{
				TS: row.TS, ProviderLabel: label, DeviceName: row.PeerName, Event: row.Event,
			})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].TS.After(all[j].TS) })
	if len(all) > limit {
		all = all[:limit]
	}
	writeOK(w, all)
}
