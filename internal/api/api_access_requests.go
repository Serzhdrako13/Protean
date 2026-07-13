package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"protean/internal/store"
	"protean/internal/vpn"
)

var errProviderNotRegistered = errors.New("provider no longer registered")

// autoProvisionableTypes are providers where approving an access request can
// safely create+assign a peer with zero manual admin input: wg-family peers
// need only a name and a free address, and the private key is generated and
// held by the panel the same way the normal "add client" flow already does.
// Cert-based providers (OpenVPN/IKEv2) need either a CSR (client keeps its
// own key) or server-side key custody as a deliberate decision, not just an
// engineering gap -- they stay on the manual approve-then-create path.
var autoProvisionableTypes = map[string]bool{"wireguard": true, "amneziawg": true}

type apiAccessRequest struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Provider string `json:"provider"`
	// ServerID is broken out as its own field (not folded into
	// ProviderLabel with an "@" suffix) so the UI can render it as a plain
	// table column -- two servers can otherwise both have a "wg0" and
	// there'd be no way to tell them apart from the label text alone.
	ServerID      string    `json:"server_id"`
	ProviderLabel string    `json:"provider_label"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

type apiAccessRequestCreateReq struct {
	Provider string `json:"provider"`
}

// POST /api/portal/requests — a portal user asks for access to one provider
// instance (or re-requests after a denial; UpsertRequest resets it to
// pending either way).
func (s *Server) apiPortalRequestAccess(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req apiAccessRequestCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "неверное тело запроса"))
		return
	}
	provider := strings.TrimSpace(req.Provider)
	prov, ok := s.reg.Get(provider)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	if prov.Type() == "xray" {
		writeErr(w, http.StatusBadRequest, msg(r, "access requests for Xray are not yet supported", "запросы доступа для Xray пока не поддерживаются"))
		return
	}
	u, err := s.store.GetUserByID(ctx, userIDFromContext(ctx))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if owned, err := s.store.ListOwnedPeerKeys(ctx, u.ID); err == nil {
		for _, o := range owned {
			if o.Provider == provider {
				writeErr(w, http.StatusBadRequest, msg(r, "you already have access to this provider", "у вас уже есть доступ к этому провайдеру"))
				return
			}
		}
	}
	ar, err := s.store.UpsertRequest(ctx, u.ID, provider)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(ctx, "access_request.create", u.Username+"/"+provider)
	writeOK(w, ar)
}

// GET /api/access-requests — admin queue of every request across all users.
func (s *Server) apiAccessRequestsList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListAllRequests(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	labels := s.instanceLabels(r.Context())
	out := make([]apiAccessRequest, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiAccessRequest{
			ID: row.ID, Username: row.Username, Provider: row.Provider, ServerID: serverPart(row.Provider),
			ProviderLabel: s.adminProviderLabel(row.Provider, labels),
			Status:        row.Status, CreatedAt: row.CreatedAt,
		})
	}
	writeOK(w, out)
}

// DELETE /api/access-requests/{id} — removes a single row from the admin
// queue. Only ever allowed for status == "denied", matching backlog item
// 1's explicit requirement: pending/approved/granted rows (anything not yet
// final, or a currently-active grant) can never be deleted here regardless
// of what the client sends.
func (s *Server) apiAccessRequestDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	req, err := s.store.GetRequest(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	if req.Status != "denied" {
		writeErr(w, http.StatusBadRequest, msg(r, "only denied requests can be deleted", "удалять можно только запросы со статусом «отказано»"))
		return
	}
	if err := s.store.DeleteRequest(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "access_request.delete", req.Username+"/"+req.Provider)
	writeOK(w, nil)
}

type apiAccessRequestClearDeniedResult struct {
	Deleted int64 `json:"deleted"`
}

// POST /api/access-requests/clear-denied — removes every currently-denied
// request in one action (backlog item 1's "or via a special separate
// button"). Reuses store.DeleteOldDeniedAccessRequests with cutoff = now,
// which matches every denied row regardless of age -- same safety
// guarantee as the single-row delete above: only ever touches 'denied'.
func (s *Server) apiAccessRequestClearDenied(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.DeleteOldDeniedAccessRequests(r.Context(), time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "access_request.clear_denied", strconv.FormatInt(n, 10))
	writeOK(w, apiAccessRequestClearDeniedResult{Deleted: n})
}

// POST /api/access-requests/{id}/deny
func (s *Server) apiAccessRequestDeny(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	req, err := s.store.GetRequest(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	if err := s.store.SetRequestStatus(r.Context(), id, "denied"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "access_request.deny", req.Username+"/"+req.Provider)
	writeOK(w, nil)
}

// POST /api/access-requests/{id}/approve — auto-provisions a peer for
// wg-family providers (see autoProvisionableTypes); everything else just
// flips to "approved" so the admin can create+link a peer manually via
// ProviderDetailPage (see apiCreatePeer's access_request_id handling).
func (s *Server) apiAccessRequestApprove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	req, err := s.store.GetRequest(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	outcome, err := s.approveRequest(ctx, req)
	if err != nil {
		if errors.Is(err, errProviderNotRegistered) {
			writeErr(w, http.StatusBadRequest, msg(r, "provider no longer registered", "провайдер больше не зарегистрирован"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeApproveOutcome(w, r, outcome)
}

// approveOutcome is what approveRequest actually did, so callers (the
// admin queue's approve button and the Users page's direct-grant action)
// can report it to the admin identically via writeApproveOutcome.
type approveOutcome struct {
	Status  string // "granted", "approved", or "approved_auto_failed"
	AutoErr error  // set only when Status == "approved_auto_failed"
}

// approveRequest is the actual approve logic, shared by an admin approving
// an already-queued request (apiAccessRequestApprove) and an admin granting
// access directly from the Users page (apiUserAccessSet) -- both paths
// go through the exact same access_request row and status transitions, per
// the explicit design choice of one table for both request-flow and direct
// grants (no separate bookkeeping to keep in sync).
func (s *Server) approveRequest(ctx context.Context, req store.AccessRequest) (approveOutcome, error) {
	prov, ok := s.reg.Get(req.Provider)
	if !ok {
		return approveOutcome{}, errProviderNotRegistered
	}
	if !autoProvisionableTypes[prov.Type()] {
		if err := s.store.SetRequestStatus(ctx, req.ID, "approved"); err != nil {
			return approveOutcome{}, err
		}
		s.audit(ctx, "access_request.approve", req.Username+"/"+req.Provider)
		return approveOutcome{Status: "approved"}, nil
	}
	if err := s.autoProvisionAndGrant(ctx, req, prov); err != nil {
		// Leave it actionable rather than stuck: fall back to the manual
		// path instead of bouncing the admin's click with a bare error.
		_ = s.store.SetRequestStatus(ctx, req.ID, "approved")
		s.audit(ctx, "access_request.approve.auto_failed", req.Username+"/"+req.Provider+": "+err.Error())
		return approveOutcome{Status: "approved_auto_failed", AutoErr: err}, nil
	}
	s.audit(ctx, "access_request.approve.auto", req.Username+"/"+req.Provider)
	return approveOutcome{Status: "granted"}, nil
}

func (s *Server) writeApproveOutcome(w http.ResponseWriter, r *http.Request, outcome approveOutcome) {
	switch outcome.Status {
	case "approved":
		writeOKMsg(w, msg(r, "approved — create a client for the user on the provider page", "одобрено — создайте клиента для пользователя на странице провайдера"), nil)
	case "approved_auto_failed":
		writeOKMsg(w, msgf(r, "automatic setup failed (%s) — create the client manually on the provider page", "автоматическая настройка не удалась (%s) — создайте клиента вручную на странице провайдера", outcome.AutoErr.Error()), nil)
	default: // "granted"
		writeOK(w, nil)
	}
}

// apiUserAccessRow is one provider instance as shown in the Users page's
// expandable per-user access panel (backlog item 15) -- unlike
// apiPortalInstance (the user's own view), this always shows the technical
// identity (type/interface/server) alongside the friendly label, since an
// admin toggling access needs to know exactly which instance they're
// touching, not just its friendly name ("admins are people too, they can
// forget which is which").
type apiUserAccessRow struct {
	Provider      string `json:"provider"`
	ProviderLabel string `json:"provider_label"`
	Type          string `json:"type"`
	Interface     string `json:"interface"`
	ServerID      string `json:"server_id"`
	Description   string `json:"description,omitempty"`
	// State mirrors apiPortalInstance's: "granted" (real peer, switch ON),
	// "approved" (admin-side "on" but cert-based providers need a manually
	// created client -- see ProviderDetailPage's pending-request banner),
	// "pending" or "denied"/"none" (switch OFF).
	State string `json:"state"`
}

// GET /api/users/{id}/access — every non-Xray provider instance and this
// user's current state on it, for the Users page's expandable access panel.
func (s *Server) apiUserAccessList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	target, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	owned, err := s.store.ListOwnedPeerKeys(ctx, target.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ownedByProvider := map[string]bool{}
	for _, o := range owned {
		ownedByProvider[o.Provider] = true
	}
	requests, err := s.store.ListRequestsForUser(ctx, target.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	reqByProvider := map[string]store.AccessRequest{}
	for _, req := range requests {
		reqByProvider[req.Provider] = req
	}
	labels := s.instanceLabels(ctx)
	descriptions := s.instanceDescriptions(ctx)

	out := []apiUserAccessRow{}
	for _, prov := range s.reg.List() {
		if prov.Type() == "xray" {
			continue
		}
		name := prov.Name()
		row := apiUserAccessRow{
			Provider: name, ProviderLabel: s.providerLabel(name, labels),
			Type: prov.Type(), Interface: localName(name), ServerID: serverPart(name),
			Description: descriptions[name], State: "none",
		}
		switch {
		case ownedByProvider[name]:
			row.State = "granted"
		case reqByProvider[name].Status == "denied":
			row.State = "denied"
		case reqByProvider[name].Status == "approved":
			row.State = "approved"
		case reqByProvider[name].Status == "pending":
			row.State = "pending"
		}
		out = append(out, row)
	}
	writeOK(w, out)
}

type apiUserAccessSetReq struct {
	Enabled bool `json:"enabled"`
}

// POST /api/users/{id}/access/{provider} — the Users page's per-provider
// access switch (backlog item 15: grant access directly, no need to wait
// for the user to request it first). enabled=true reuses the exact same
// create-or-reopen-then-approve path as the portal's own request flow
// (approveRequest) -- a directly-granted provider is indistinguishable
// from one the user requested and an admin approved. enabled=false revokes:
// removes any real peer host-side and marks the request denied. Both
// directions act on the SAME access_request row/table as the request flow,
// so there is no separate state to drift out of sync.
func (s *Server) apiUserAccessSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	target, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	if target.Role != "user" {
		writeErr(w, http.StatusBadRequest, msg(r, "access can only be granted to portal (\"user\" role) accounts", "доступ можно предоставить только учётным записям портала (роль \"user\")"))
		return
	}
	provider := r.PathValue("provider")
	prov, ok := s.reg.Get(provider)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	if prov.Type() == "xray" {
		writeErr(w, http.StatusBadRequest, msg(r, "access requests for Xray are not yet supported", "запросы доступа для Xray пока не поддерживаются"))
		return
	}
	var req apiUserAccessSetReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}

	if !req.Enabled {
		s.revokeUserProviderAccess(ctx, target.ID, provider)
		s.audit(ctx, "access_request.revoke_direct", target.Username+"/"+provider)
		writeOK(w, nil)
		return
	}

	if owned, err := s.store.ListOwnedPeerKeys(ctx, target.ID); err == nil {
		for _, o := range owned {
			if o.Provider == provider {
				writeOK(w, nil) // already granted -- idempotent no-op, not an error
				return
			}
		}
	}
	ar, err := s.store.UpsertRequest(ctx, target.ID, provider)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// UpsertRequest's RETURNING clause doesn't join username (it isn't
	// needed by the portal's own request flow, which always acts on the
	// calling user) -- approveRequest needs it for the peer name + audit
	// messages, so fill it in from the user row we already fetched.
	ar.Username = target.Username
	s.audit(ctx, "access_request.grant_direct", target.Username+"/"+provider)
	outcome, err := s.approveRequest(ctx, ar)
	if err != nil {
		if errors.Is(err, errProviderNotRegistered) {
			writeErr(w, http.StatusBadRequest, msg(r, "provider no longer registered", "провайдер больше не зарегистрирован"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeApproveOutcome(w, r, outcome)
}

// revokeUserProviderAccess revokes ONE user's access to ONE provider: if a
// peer exists there, removes it host-side and clears ownership; either way
// marks the access_request row (if any) "denied". Best-effort, same
// soft-failure philosophy as removeUserPeers/denyUserRequests (account
// disable's all-providers equivalent in api_users.go) -- an unreachable
// host shouldn't block the admin's toggle.
func (s *Server) revokeUserProviderAccess(ctx context.Context, userID int64, provider string) {
	if owned, err := s.store.ListOwnedPeerKeys(ctx, userID); err == nil {
		for _, o := range owned {
			if o.Provider != provider {
				continue
			}
			if prov, ok := s.reg.Get(o.Provider); ok {
				if pubkey, derr := decodePeerID(o.PeerKey); derr == nil {
					if err := prov.RemovePeer(ctx, pubkey); err != nil {
						slog.Warn("revoke user provider access: remove peer", "provider", o.Provider, "err", err)
					}
					s.invalidateStatus(o.Provider)
				}
			}
			if err := s.store.ClearPeerOwner(ctx, o.Provider, o.PeerKey); err != nil {
				slog.Warn("revoke user provider access: clear owner", "provider", o.Provider, "err", err)
			}
		}
	} else {
		slog.Warn("revoke user provider access: list owned", "user_id", userID, "err", err)
	}
	if requests, err := s.store.ListRequestsForUser(ctx, userID); err == nil {
		for _, req := range requests {
			if req.Provider == provider && req.Status != "denied" {
				if err := s.store.SetRequestStatus(ctx, req.ID, "denied"); err != nil {
					slog.Warn("revoke user provider access: set status", "id", req.ID, "err", err)
				}
			}
		}
	}
}

// autoProvisionAndGrant creates a peer, assigns it to the requesting user,
// and only flips the request to "granted" once a basic sanity check (can we
// actually build a downloadable config for it?) passes -- mirrors
// apiCreatePeer's own key-sealing so the result is indistinguishable from a
// manually-created peer.
// autoProvisionPeer creates a peer with an auto-picked free address on an
// auto-provisionable (wg-family) provider instance -- the mechanical core
// shared by the access-request auto-grant path (autoProvisionAndGrant
// below) and the node-grant path (api_nodes.go). Callers still own
// sanity-checking the result (buildPeerDownload) and recording ownership
// (SetPeerOwner / SetNodePeer) in their own table.
func (s *Server) autoProvisionPeer(ctx context.Context, providerName string, prov vpn.Provider, name string) (urlID string, result vpn.NewPeerResult, err error) {
	status, err := prov.Status(ctx)
	if err != nil {
		return "", vpn.NewPeerResult{}, fmt.Errorf("read server status: %w", err)
	}
	cidr := vpn.FirstCIDR(status.Address)
	if cidr == "" {
		return "", vpn.NewPeerResult{}, fmt.Errorf("server has no configured address/subnet yet")
	}
	peers, err := prov.ListPeers(ctx)
	if err != nil {
		return "", vpn.NewPeerResult{}, fmt.Errorf("list existing peers: %w", err)
	}
	used := map[string]bool{}
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			if ip, _, err := net.ParseCIDR(a); err == nil {
				used[ip.String()] = true
			}
		}
	}
	if serverIP, _, err := net.ParseCIDR(cidr); err == nil {
		used[serverIP.String()] = true // never hand out the server's own address
	}
	settings, err := s.store.GetProviderSettings(ctx, providerName)
	if err != nil {
		return "", vpn.NewPeerResult{}, fmt.Errorf("read provider settings: %w", err)
	}
	freeIP, err := vpn.NextFreeIPInRange(cidr, settings.AutoAssignStart, settings.AutoAssignEnd, used)
	if err != nil {
		return "", vpn.NewPeerResult{}, fmt.Errorf("allocate address: %w", err)
	}

	result, err = prov.AddPeer(ctx, vpn.PeerSpec{Name: name, AllowedIPs: []string{freeIP}, PersistentKeepalive: 25})
	if err != nil {
		return "", vpn.NewPeerResult{}, fmt.Errorf("create peer: %w", err)
	}
	if result.Peer.PublicKey == "" {
		return "", vpn.NewPeerResult{}, fmt.Errorf("provider returned a peer with no identifier")
	}

	blob, err := s.enc.Seal(result.PrivateKey)
	if err != nil {
		_ = prov.RemovePeer(ctx, result.Peer.PublicKey)
		return "", vpn.NewPeerResult{}, fmt.Errorf("seal private key: %w", err)
	}
	if err := s.store.SavePeerSecret(ctx, providerName, result.Peer.PublicKey, blob); err != nil {
		_ = prov.RemovePeer(ctx, result.Peer.PublicKey)
		return "", vpn.NewPeerResult{}, fmt.Errorf("store private key: %w", err)
	}

	urlID, err = encodePeerID(result.Peer.PublicKey)
	if err != nil {
		return "", vpn.NewPeerResult{}, fmt.Errorf("encode peer id: %w", err)
	}
	return urlID, result, nil
}

func (s *Server) autoProvisionAndGrant(ctx context.Context, req store.AccessRequest, prov vpn.Provider) error {
	urlID, result, err := s.autoProvisionPeer(ctx, req.Provider, prov, req.Username)
	if err != nil {
		return err
	}
	if err := s.store.SetPeerOwner(ctx, req.Provider, urlID, req.UserID); err != nil {
		return fmt.Errorf("assign owner: %w", err)
	}

	if _, _, _, err := s.buildPeerDownload(ctx, req.Provider, result.Peer.PublicKey, ""); err != nil {
		return fmt.Errorf("post-creation check failed: %w", err)
	}

	if err := s.store.SetRequestStatus(ctx, req.ID, "granted"); err != nil {
		return fmt.Errorf("mark granted: %w", err)
	}
	s.invalidateStatus(req.Provider)
	return nil
}
