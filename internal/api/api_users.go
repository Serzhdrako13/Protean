package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"protean/internal/auth"
)

type apiUser struct {
	ID                  int64     `json:"id"`
	Username            string    `json:"username"`
	Role                string    `json:"role"`
	CreatedAt           time.Time `json:"created_at"`
	Enabled             bool      `json:"enabled"`
	PortalAccessEnabled bool      `json:"portal_access_enabled"`
}

// GET /api/users
func (s *Server) apiUsersList(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiUser, 0, len(users))
	for _, u := range users {
		out = append(out, apiUser{
			ID: u.ID, Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt,
			Enabled: u.Enabled, PortalAccessEnabled: u.PortalAccessEnabled,
		})
	}
	writeOK(w, out)
}

type apiUserCreateReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// POST /api/users -- creates a portal ("user") or a second admin account.
func (s *Server) apiUsersCreate(w http.ResponseWriter, r *http.Request) {
	var req apiUserCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "username required", "требуется имя пользователя"))
		return
	}
	role := req.Role
	if role == "" {
		role = "user"
	}
	if role != "admin" && role != "user" {
		writeErr(w, http.StatusBadRequest, msg(r, "role must be \"admin\" or \"user\"", "роль должна быть \"admin\" или \"user\""))
		return
	}
	if err := s.auth.CreateUser(r.Context(), username, req.Password, role); err != nil {
		writeErr(w, http.StatusBadRequest, auth.PolicyErrorMessage(err, requestLang(r)))
		return
	}
	u, err := s.store.GetUserByUsernameAndSource(r.Context(), username, "local")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "user.create", username+"/"+role)
	writeOK(w, apiUser{
		ID: u.ID, Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt,
		Enabled: u.Enabled, PortalAccessEnabled: u.PortalAccessEnabled,
	})
}

// DELETE /api/users/{id}
func (s *Server) apiUsersDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	// Checked before the self-delete guard below: with only one admin
	// left, that admin IS necessarily the caller (only admins can reach
	// this route), so checking self first would always mask this with the
	// less specific "can't delete your own account" message.
	if target.Role == "admin" {
		n, err := s.store.CountUsersByRole(r.Context(), "admin")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if n <= 1 {
			writeErr(w, http.StatusBadRequest, msg(r, "can't delete the last admin account", "нельзя удалить последнего администратора"))
			return
		}
	}
	if target.ID == userIDFromContext(r.Context()) {
		writeErr(w, http.StatusBadRequest, msg(r, "can't delete your own account", "нельзя удалить собственную учётную запись"))
		return
	}
	// Real host-side cleanup before the row (and its peer_owner/access_request
	// rows, via ON DELETE CASCADE) disappears -- otherwise a deleted user's
	// WireGuard/OpenVPN/IKEv2 peers would keep working forever, orphaned on
	// the host with no panel-side record of who they belonged to.
	s.removeUserPeers(r.Context(), id)
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// audit_log has no FK to users (see its migration) -- this row is
	// permanent, exactly matching the requirement that a deletion record
	// itself must never be cleaned up even though everything else is gone.
	s.audit(r.Context(), "user.delete", target.Username)
	writeOK(w, nil)
}

// removeUserPeers revokes (host-side) every peer a user owns and clears
// their peer_owner rows -- shared by full delete and account-disable.
// Best-effort: a single unreachable host shouldn't block deleting/disabling
// the account, so failures are logged, not returned.
func (s *Server) removeUserPeers(ctx context.Context, userID int64) {
	owned, err := s.store.ListOwnedPeerKeys(ctx, userID)
	if err != nil {
		slog.Warn("remove user peers: list owned", "user_id", userID, "err", err)
		return
	}
	for _, o := range owned {
		if prov, ok := s.reg.Get(o.Provider); ok {
			if pubkey, derr := decodePeerID(o.PeerKey); derr == nil {
				if err := prov.RemovePeer(ctx, pubkey); err != nil {
					slog.Warn("remove user peers: remove peer", "provider", o.Provider, "err", err)
				}
				// The provider status/peer-list cache (statuscache.go) has
				// its own short TTL -- without this, the admin UI can show
				// a just-removed peer as still present for a few seconds.
				s.invalidateStatus(o.Provider)
			}
		}
		if err := s.store.ClearPeerOwner(ctx, o.Provider, o.PeerKey); err != nil {
			slog.Warn("remove user peers: clear owner", "provider", o.Provider, "err", err)
		}
	}
}

// denyUserRequests flips every access_request a (now peer-less) user has to
// "denied" -- used only when disabling an account, so the portal and admin
// queue reflect that access was pulled rather than showing a stale
// "granted"/"pending" state for a peer that no longer exists.
func (s *Server) denyUserRequests(ctx context.Context, userID int64) {
	requests, err := s.store.ListRequestsForUser(ctx, userID)
	if err != nil {
		slog.Warn("deny user requests: list", "user_id", userID, "err", err)
		return
	}
	for _, req := range requests {
		if req.Status == "denied" {
			continue
		}
		if err := s.store.SetRequestStatus(ctx, req.ID, "denied"); err != nil {
			slog.Warn("deny user requests: set status", "id", req.ID, "err", err)
		}
	}
}

type apiUserStatusReq struct {
	Enabled bool `json:"enabled"`
}

// POST /api/users/{id}/enabled — enable/disable an account (backlog item
// 2's "account disabled, providers stop working" state). Disabling blocks
// ALL login (any role) and immediately revokes every VPN peer this account
// owns; re-enabling only restores login -- peers must be re-granted, they
// aren't recreated automatically.
func (s *Server) apiUsersSetEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiUserStatusReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if !req.Enabled {
		if target.ID == userIDFromContext(r.Context()) {
			writeErr(w, http.StatusBadRequest, msg(r, "can't disable your own account", "нельзя отключить собственную учётную запись"))
			return
		}
		if target.Role == "admin" {
			all, err := s.store.ListUsers(r.Context())
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			enabledAdmins := 0
			for _, u := range all {
				if u.Role == "admin" && u.Enabled {
					enabledAdmins++
				}
			}
			if enabledAdmins <= 1 {
				writeErr(w, http.StatusBadRequest, msg(r, "can't disable the last admin account", "нельзя отключить последнего администратора"))
				return
			}
		}
	}
	if err := s.store.UpdateUserEnabled(r.Context(), id, req.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !req.Enabled {
		s.removeUserPeers(r.Context(), id)
		s.denyUserRequests(r.Context(), id)
	}
	s.audit(r.Context(), "user.set_enabled", target.Username+"="+strconv.FormatBool(req.Enabled))
	writeOK(w, nil)
}

// POST /api/users/{id}/portal-access — allow/deny the self-service portal
// specifically (backlog item 2's "portal access denied" state). Unlike
// apiUsersSetEnabled, this leaves any existing VPN peers running -- only
// the portal login path (role == "user") is ever gated by it.
func (s *Server) apiUsersSetPortalAccess(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiUserStatusReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.store.UpdateUserPortalAccess(r.Context(), id, req.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "user.set_portal_access", target.Username+"="+strconv.FormatBool(req.Enabled))
	writeOK(w, nil)
}

type apiUserResetPasswordReq struct {
	NewPassword string `json:"new_password"`
}

// POST /api/users/{id}/reset-password
func (s *Server) apiUsersResetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiUserResetPasswordReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.auth.AdminSetPassword(r.Context(), target.Username, req.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, auth.PolicyErrorMessage(err, requestLang(r)))
		return
	}
	s.audit(r.Context(), "user.reset_password", target.Username)
	writeOK(w, nil)
}

type apiPeerOwnerReq struct {
	UserID int64 `json:"user_id"`
}

// POST /api/providers/{provider}/peers/{id}/owner -- assign (user_id > 0) or
// unassign (user_id == 0) a peer to a portal user, for the self-service
// portal's "my devices" list.
func (s *Server) apiPeerSetOwner(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	peerID := r.PathValue("id")
	if !s.instanceExists(provider) {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	var req apiPeerOwnerReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.UserID == 0 {
		if err := s.store.ClearPeerOwner(r.Context(), provider, peerID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r.Context(), "peer.owner.clear", provider+"/"+peerID)
		writeOK(w, nil)
		return
	}
	owner, err := s.store.GetUserByID(r.Context(), req.UserID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "unknown user", "неизвестный пользователь"))
		return
	}
	if owner.Role != "user" {
		writeErr(w, http.StatusBadRequest, msg(r, "peers can only be assigned to portal (\"user\" role) accounts", "устройства можно назначать только учётным записям портала (роль \"user\")"))
		return
	}
	if _, has, err := s.store.GetNodePeerOwnerID(r.Context(), provider, peerID); err == nil && has {
		writeErr(w, http.StatusBadRequest, msg(r, "this client already has a node owner -- clear it first", "у этого клиента уже есть владелец-узел, сначала снимите его"))
		return
	}
	if err := s.store.SetPeerOwner(r.Context(), provider, peerID, req.UserID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "peer.owner.set", provider+"/"+peerID+" -> "+owner.Username)
	writeOK(w, nil)
}
