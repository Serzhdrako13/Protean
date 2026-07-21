package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"protean/internal/store"
	"protean/internal/vpn"
)

type apiHomeProvider struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	Label       string `json:"label"`
	Up          bool   `json:"up"`
	Peers       int    `json:"peers"`
	PeersOnline int    `json:"peers_online"`
}

type apiHomeServer struct {
	ID        string            `json:"id"`
	Label     string            `json:"label"`
	Host      string            `json:"host"`
	Providers []apiHomeProvider `json:"providers"`
	RxBytes   uint64            `json:"rx_bytes"`
	TxBytes   uint64            `json:"tx_bytes"`
}

type apiHome struct {
	HasServers   bool            `json:"has_servers"`
	Servers      []apiHomeServer `json:"servers"`
	ServersUp    int             `json:"servers_up"`
	ServersTotal int             `json:"servers_total"`
	PeersOnline  int             `json:"peers_online"`
	PeersTotal   int             `json:"peers_total"`
	TotalRxBytes uint64          `json:"total_rx_bytes"`
	TotalTxBytes uint64          `json:"total_tx_bytes"`
}

// GET /api/dashboard — aggregate stat-tile + per-server/provider summary data
// for the SPA's Index page (same source data as the server-rendered home
// dashboard in handlers_dashboard.go's handleRoot).
func (s *Server) apiDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, err := s.store.ListServers(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	home := apiHome{HasServers: len(servers) > 0}
	labels := s.instanceLabels(ctx)
	for _, srv := range servers {
		// Providers initialized non-nil: a server can now genuinely have
		// zero provider instances (e.g. added purely for SSH-based
		// management, or a panel-host row) -- a nil slice serializes as
		// JSON null, and the frontend calls .reduce/.filter/.length on
		// srv.providers unconditionally, which throws on null.
		sv := apiHomeServer{ID: srv.ID, Label: srv.Label, Host: srv.Host, Providers: []apiHomeProvider{}}
		serverUp := false
		for _, prov := range s.reg.List() {
			if serverPart(prov.Name()) != srv.ID {
				continue
			}
			pv := apiHomeProvider{Key: prov.Name(), Type: prov.Type(), Label: s.adminProviderLabel(prov.Name(), labels)}
			if st, err := s.providerStatus(ctx, prov); err == nil {
				pv.Up = st.Up
				pv.Peers = st.PeerCount
				pv.PeersOnline = st.PeersOnline
				if st.Up {
					serverUp = true
					home.PeersOnline += st.PeersOnline
					home.PeersTotal += st.PeerCount
					home.TotalRxBytes += st.TotalRxBytes
					home.TotalTxBytes += st.TotalTxBytes
					sv.RxBytes += st.TotalRxBytes
					sv.TxBytes += st.TotalTxBytes
				}
			}
			sv.Providers = append(sv.Providers, pv)
		}
		if serverUp {
			home.ServersUp++
		}
		home.ServersTotal++
		home.Servers = append(home.Servers, sv)
	}
	writeOK(w, home)
}

type apiProviderSummary struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Label string `json:"label"`
	// FriendlyLabel is JUST the admin-set friendly name (empty if unset) --
	// unlike Label (which bundles it with the technical type/interface for
	// display contexts that only have room for one column), this is for
	// tables that show type/interface as their OWN separate columns and
	// would otherwise show that information twice.
	FriendlyLabel string           `json:"friendly_label,omitempty"`
	ServerID      string           `json:"server_id"`
	Status        vpn.ServerStatus `json:"status"`
	CertBased     bool             `json:"cert_based"`
	// PortalVisible: whether this instance is opted into the self-service
	// portal (see protean.server_instances.portal_visible).
	PortalVisible bool `json:"portal_visible"`
	// Description is the admin-set note shown to portal users (empty if unset).
	Description string `json:"description,omitempty"`
}

// GET /api/providers — one row per provider instance across all servers
// (the SPA's "Inbounds" analog). Errors from an individual provider's status
// call are swallowed per-row (Up stays false) rather than failing the whole
// list, same as the home dashboard's degrade-not-500 behavior.
func (s *Server) apiProvidersList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list := s.reg.List()
	labels := s.instanceLabels(ctx)
	visible := s.instancePortalVisibility(ctx)
	descriptions := s.instanceDescriptions(ctx)
	out := make([]apiProviderSummary, 0, len(list))
	for _, prov := range list {
		_, certBased := prov.(vpn.ClientConfigProvider)
		row := apiProviderSummary{
			Key: prov.Name(), Type: prov.Type(), Label: s.adminProviderLabel(prov.Name(), labels),
			FriendlyLabel: labels[prov.Name()],
			ServerID:      serverPart(prov.Name()), CertBased: certBased, PortalVisible: visible[prov.Name()],
			Description: descriptions[prov.Name()],
		}
		if st, err := s.providerStatus(ctx, prov); err == nil {
			row.Status = st
		}
		out = append(out, row)
	}
	writeOK(w, out)
}

type apiProviderDetail struct {
	Provider         string           `json:"provider"`
	ProviderLabel    string           `json:"provider_label"`
	Type             string           `json:"type"`
	Status           vpn.ServerStatus `json:"status"`
	Peers            []PeerView       `json:"peers"`
	NotImplemented   bool             `json:"not_implemented"`
	CertBased        bool             `json:"cert_based"`
	ProfileFormats   []string         `json:"profile_formats,omitempty"`
	NeedsSetup       bool             `json:"needs_setup"`
	PeersUnavailable bool             `json:"peers_unavailable"`
	// SupportsBackups: config-file backup/restore (wg-family only — a
	// certificate-based provider has no single flat conf file to snapshot).
	SupportsBackups bool `json:"supports_backups"`
	// PendingApprovedRequest is set when a portal user's access request for
	// THIS provider was approved but no peer has been created for them yet
	// (always true for cert-based providers; only happens for wg-family if
	// auto-provisioning's sanity check failed) — the UI prompts the admin to
	// create+link a client for them.
	PendingApprovedRequest *apiPendingRequest `json:"pending_approved_request,omitempty"`
}

type apiPendingRequest struct {
	RequestID int64  `json:"request_id"`
	Username  string `json:"username"`
}

// GET /api/providers/{provider} — provider status + full peer list.
func (s *Server) apiProviderDetail(w http.ResponseWriter, r *http.Request) {
	detail, err := s.buildAPIProviderDetail(r, r.PathValue("provider"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeOK(w, detail)
}

// buildAPIProviderDetail is apiProviderDetail's pure-logic half (no
// response-writing), so it's directly unit-testable — mirrors the old
// buildDashboardView (handlers_dashboard.go, removed in the SPA cutover).
func (s *Server) buildAPIProviderDetail(r *http.Request, providerName string) (apiProviderDetail, error) {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return apiProviderDetail{}, fmt.Errorf("unknown provider %q", providerName)
	}
	detail := apiProviderDetail{
		Provider: providerName, ProviderLabel: s.adminProviderLabel(providerName, s.instanceLabels(r.Context())), Type: prov.Type(),
	}
	_, detail.CertBased = prov.(vpn.ClientConfigProvider)
	_, detail.SupportsBackups = prov.(vpn.ConfRestorer)
	if cpp, ok := prov.(vpn.ClientProfileProvider); ok {
		detail.ProfileFormats = cpp.ProfileFormats()
	}
	if s.store != nil {
		if ar, found, err := s.store.FindApprovedRequestForProvider(r.Context(), providerName); err == nil && found {
			detail.PendingApprovedRequest = &apiPendingRequest{RequestID: ar.ID, Username: ar.Username}
		}
	}

	status, err := s.providerStatus(r.Context(), prov)
	if err != nil {
		if errors.Is(err, vpn.ErrNotImplemented) {
			detail.NotImplemented = true
			return detail, nil
		}
		return apiProviderDetail{}, err
	}
	detail.Status = status
	if !status.Up {
		// wg-family also needs setup when down -- either genuinely never
		// bootstrapped (see provisionWGFamily/EnsureServer) or just
		// stopped; offering "Setup" in the latter case is a harmless no-op
		// click (EnsureServer does nothing once a conf already exists),
		// same imprecision cert-based already has here.
		detail.NeedsSetup = detail.CertBased || prov.Type() == "wireguard" || prov.Type() == "amneziawg"
		// Peers already known to the panel (soft-disabled wg-family peers,
		// tracked in the DB regardless of live host reachability) still show
		// up while the interface itself is down -- e.g. so an admin can
		// still assign/reassign portal ownership without needing the
		// interface up first.
		if s.store != nil {
			s.appendDisabledPeersJSON(r.Context(), &detail.Peers, providerName)
		}
		return detail, nil
	}

	peers, err := s.providerPeers(r.Context(), prov)
	if err != nil {
		detail.PeersUnavailable = true
		if s.store != nil {
			s.appendDisabledPeersJSON(r.Context(), &detail.Peers, providerName)
		}
		return detail, nil
	}
	expiry := map[string]time.Time{}
	muted := map[string]bool{}
	cats := map[string]string{}
	owners := map[string]store.PeerOwnerRow{}
	nodeOwners := map[string]store.NodePeerRow{}
	if s.store != nil {
		expiry, _ = s.store.ExpiryForProvider(r.Context(), providerName)
		muted, _ = s.store.MutedPeers(r.Context(), providerName)
		cats, _ = s.store.PeerCategories(r.Context(), providerName)
		if rows, err := s.store.ListOwnersForProvider(r.Context(), providerName); err == nil {
			for _, row := range rows {
				owners[row.PeerKey] = row
			}
		}
		if rows, err := s.store.ListNodeOwnersForProvider(r.Context(), providerName); err == nil {
			for _, row := range rows {
				nodeOwners[row.PeerKey] = row
			}
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	for _, p := range peers {
		urlID, err := encodePeerID(p.PublicKey)
		if err != nil {
			continue
		}
		owner := owners[urlID]
		nodeOwner := nodeOwners[urlID]
		detail.Peers = append(detail.Peers, PeerView{
			URLID: urlID, Name: p.Name, Online: p.Online, Endpoint: p.Endpoint,
			AllowedIPs: p.AllowedIPs, LastHandshake: p.LastHandshake,
			RxBytes: p.RxBytes, TxBytes: p.TxBytes, PersistentKeepalive: p.PersistentKeepalive,
			P12Password: p.Extra["p12password"], ExpiresAt: expiry[p.PublicKey],
			Muted: muted[p.PublicKey], Category: cats[p.PublicKey],
			OwnerUserID: owner.UserID, OwnerUsername: owner.Username,
			NodeOwnerID: nodeOwner.NodeID, NodeOwnerName: nodeOwner.NodeName,
		})
	}
	if s.store != nil {
		s.appendDisabledPeersJSON(r.Context(), &detail.Peers, providerName)
	}
	return detail, nil
}

// appendDisabledPeersJSON is appendDisabledPeers's JSON-response twin: same
// store lookup, appends into a []PeerView slice instead of a dashboardView.
func (s *Server) appendDisabledPeersJSON(ctx context.Context, peers *[]PeerView, providerName string) {
	disabled, err := s.store.ListDisabledPeers(ctx, providerName)
	if err != nil {
		slog.Error("api dashboard: list disabled peers", "provider", providerName, "err", err)
		return
	}
	owners := map[string]store.PeerOwnerRow{}
	if rows, err := s.store.ListOwnersForProvider(ctx, providerName); err == nil {
		for _, row := range rows {
			owners[row.PeerKey] = row
		}
	}
	nodeOwners := map[string]store.NodePeerRow{}
	if rows, err := s.store.ListNodeOwnersForProvider(ctx, providerName); err == nil {
		for _, row := range rows {
			nodeOwners[row.PeerKey] = row
		}
	}
	for _, dp := range disabled {
		urlID, err := encodePeerID(dp.PublicKey)
		if err != nil {
			continue
		}
		var allowed []string
		if dp.AllowedIPs != "" {
			allowed = strings.Split(dp.AllowedIPs, ",")
		}
		owner := owners[urlID]
		nodeOwner := nodeOwners[urlID]
		*peers = append(*peers, PeerView{
			URLID: urlID, Name: dp.Name, Disabled: true,
			AllowedIPs: allowed, PersistentKeepalive: dp.Keepalive,
			OwnerUserID: owner.UserID, OwnerUsername: owner.Username,
			NodeOwnerID: nodeOwner.NodeID, NodeOwnerName: nodeOwner.NodeName,
		})
	}
}
