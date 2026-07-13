package api

import (
	"errors"
	"fmt"
	"net/http"

	"protean/internal/store"
)

type apiAdminPortalPeer struct {
	Username string `json:"username"`
	PeerKey  string `json:"peer_key"`
	Name     string `json:"name"`
	Online   bool   `json:"online"`
}

type apiAdminPortalInstance struct {
	Provider      string               `json:"provider"`
	ServerID      string               `json:"server_id"`
	ProviderLabel string               `json:"provider_label"`
	PortalVisible bool                 `json:"portal_visible"`
	Peers         []apiAdminPortalPeer `json:"peers"`
}

// GET /api/admin-portal — every instance that has at least one assigned
// peer, regardless of portal_visible -- unlike the self-service portal
// (which hides non-visible instances from regular users entirely), an
// admin needs to see and download configs for hidden networks too. Reuses
// the exact same download/QR logic as the self-service portal
// (buildPeerDownload/buildPeerQRPNG below) instead of duplicating it; no
// per-row ownership check is needed since this whole section is already
// admin-only (role=="user" 403s on anything outside /api/portal/*, see
// requireAuthAPI's role gate) -- same trust boundary as the existing
// per-provider peer table, which has never required ownership either.
func (s *Server) apiAdminPortalList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	owned, err := s.store.ListAllOwnedPeers(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	byProvider := map[string][]store.GlobalPeerOwnerRow{}
	for _, o := range owned {
		byProvider[o.Provider] = append(byProvider[o.Provider], o)
	}

	labels := s.instanceLabels(ctx)
	visible := s.instancePortalVisibility(ctx)
	out := []apiAdminPortalInstance{}
	for _, prov := range s.reg.List() {
		if prov.Type() == "xray" {
			continue
		}
		name := prov.Name()
		rows := byProvider[name]
		if len(rows) == 0 {
			continue
		}
		inst := apiAdminPortalInstance{
			Provider: name, ServerID: serverPart(name),
			ProviderLabel: s.adminProviderLabel(name, labels),
			PortalVisible: visible[name],
		}
		for _, row := range rows {
			pp := apiAdminPortalPeer{Username: row.Username, PeerKey: row.PeerKey}
			if pubkey, err := decodePeerID(row.PeerKey); err == nil {
				if peer, err := s.findPeer(ctx, prov, pubkey); err == nil {
					pp.Name = peer.Name
					pp.Online = peer.Online
				}
			}
			inst.Peers = append(inst.Peers, pp)
		}
		out = append(out, inst)
	}
	writeOK(w, out)
}

// GET /api/admin-portal/peers/{provider}/{key}/config
func (s *Server) apiAdminPortalPeerConfig(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	key := r.PathValue("key")
	pubkey, err := decodePeerID(key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	format := r.URL.Query().Get("format")
	s.audit(r.Context(), "admin_portal.peer.config.download", provider+"/"+key)
	contentType, filename, data, err := s.buildPeerDownload(r.Context(), provider, pubkey, format)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNoAltProfile) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write(data)
}

// GET /api/admin-portal/peers/{provider}/{key}/qr
func (s *Server) apiAdminPortalPeerQR(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	key := r.PathValue("key")
	pubkey, err := decodePeerID(key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.audit(r.Context(), "admin_portal.peer.config.qr", provider+"/"+key)
	png, err := s.buildPeerQRPNG(r.Context(), provider, pubkey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}
