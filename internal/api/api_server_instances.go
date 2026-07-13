package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"protean/internal/store"
	"protean/internal/vpn"
)

// singleInstanceTypes mirrors servers.singleInstanceTypes (kept as a small,
// separately-defined map here rather than importing internal/servers, which
// this package deliberately doesn't depend on — see the local ServerManager
// interface in server.go). ikev2 shares one strongSwan daemon per server
// regardless of connection name; xray's installer only sets up a single
// systemd unit + config path. Both capped at 1 until the installer script
// grows per-instance systemd templating.
var singleInstanceTypes = map[string]bool{"ikev2": true, "xray": true}

var validInstanceName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

type apiServerInstance struct {
	LocalName string            `json:"local_name"`
	Type      string            `json:"type"`
	Config    map[string]string `json:"config,omitempty"`
	// Label is an admin-settable friendly name shown to portal users
	// instead of the raw local_name (e.g. "Германия" instead of "wg1").
	Label string `json:"label,omitempty"`
	// PortalVisible: whether this instance can be requested/seen at all in
	// the self-service portal. Defaults false -- explicit opt-in per instance.
	PortalVisible bool `json:"portal_visible"`
	// Description is an admin-settable freeform note shown to portal users
	// alongside the label (e.g. "домашняя сеть, egress запрещён").
	Description string `json:"description,omitempty"`
}

// GET /api/servers/{id}/instances
func (s *Server) apiServerInstancesList(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	rows, err := s.store.ListServerInstances(r.Context(), serverID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiServerInstance, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiServerInstance{
			LocalName: row.LocalName, Type: row.Type, Config: row.Config,
			Label: row.Label, PortalVisible: row.PortalVisible, Description: row.Description,
		})
	}
	writeOK(w, out)
}

// validateWGFamilyCreate checks the safety invariants for a brand-new
// WireGuard/AmneziaWG instance's Config (see provisionWGFamily/
// wgfamily.Provider.EnsureServer, which is what actually consumes these
// values once the admin clicks Setup): an address is required (the
// interface can't come up without one), it must not overlap any other
// tunnel CIDR anywhere in the mesh, and its listen_port (if explicitly
// set) must not collide with another instance's explicit listen_port on
// THE SAME server (different servers may reuse ports freely; wg itself
// picks a random port at runtime when listen_port is left empty, so two
// unset ports never collide).
func (s *Server) validateWGFamilyCreate(r *http.Request, serverID string, cfg map[string]string) error {
	address := strings.TrimSpace(cfg["address"])
	if address == "" {
		return errors.New(msg(r, "address is required for WireGuard/AmneziaWG", "для WireGuard/AmneziaWG требуется адрес"))
	}
	if err := vpn.CheckNoOverlap(address, s.allTunnelCIDRs(r.Context(), "")); err != nil {
		return errors.New(msgf(r, "address overlaps an existing tunnel: %v", "адрес пересекается с существующим туннелем: %v", err))
	}
	port := strings.TrimSpace(cfg["listen_port"])
	if port == "" {
		return nil
	}
	portN, err := strconv.Atoi(port)
	if err != nil {
		return errors.New(msg(r, "listen_port must be a number", "listen_port должен быть числом"))
	}
	instances, ierr := s.store.ListServerInstances(r.Context(), serverID)
	if ierr != nil {
		return ierr
	}
	for _, inst := range instances {
		if inst.Type != "wireguard" && inst.Type != "amneziawg" {
			continue
		}
		if existing := strings.TrimSpace(inst.Config["listen_port"]); existing != "" {
			if existingN, err := strconv.Atoi(existing); err == nil && existingN == portN {
				return errors.New(msgf(r, "listen_port %d is already used by %s on this server", "listen_port %d уже используется провайдером %s на этом сервере", portN, inst.LocalName))
			}
		}
	}
	return nil
}

// POST /api/servers/{id}/instances — register a new VPN instance on a
// server (backlog item 7: was env-var/deploy-time only, now DB-backed and
// editable per server). ikev2/xray are capped at one per server (see
// singleInstanceTypes); wireguard/amneziawg/openvpn are unlimited — each
// already runs as its own systemd unit instance.
func (s *Server) apiServerInstancesCreate(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	if _, err := s.store.GetServer(r.Context(), serverID); err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "unknown server", "неизвестный сервер"))
		return
	}
	var req apiServerInstance
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if !isKnownProviderType(req.Type) {
		writeErr(w, http.StatusBadRequest, msg(r, "unknown provider type", "неизвестный тип провайдера"))
		return
	}
	localName := strings.TrimSpace(req.LocalName)
	if !validInstanceName.MatchString(localName) {
		writeErr(w, http.StatusBadRequest, msg(r, "provider name must be lowercase letters/digits/-/_, starting with a letter", "имя провайдера должно состоять из строчных букв/цифр/-/_ и начинаться с буквы"))
		return
	}
	if singleInstanceTypes[req.Type] {
		n, err := s.store.CountServerInstancesByType(r.Context(), serverID, req.Type)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if n > 0 {
			writeErr(w, http.StatusBadRequest, msgf(r, "%s supports only one instance per server (see the hint)", "%s поддерживает только один провайдер на сервер (см. подсказку)", typeLabel(req.Type)))
			return
		}
	}
	if req.Type == "wireguard" || req.Type == "amneziawg" {
		if err := s.validateWGFamilyCreate(r, serverID, req.Config); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	inst := store.ServerInstance{
		ServerID: serverID, LocalName: localName, Type: req.Type, Config: req.Config,
		Label: strings.TrimSpace(req.Label), Description: strings.TrimSpace(req.Description),
	}
	if err := s.store.CreateServerInstance(r.Context(), inst); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "server_instance.create", serverID+"/"+localName)
	if s.mgr != nil {
		if err := s.mgr.Rebuild(r.Context(), serverID); err != nil {
			writeOKMsg(w, msgf(r, "instance saved, but registering it failed: %v", "провайдер сохранён, но зарегистрировать его не удалось: %v", err), nil)
			return
		}
	}
	writeOK(w, inst)
}

type apiServerInstanceLabelReq struct {
	Label string `json:"label"`
}

// PUT /api/servers/{id}/instances/{name} — rename an existing instance's
// friendly label. This is the only way to label instances that were
// auto-seeded before this feature existed (create-time labeling alone
// wouldn't cover them).
func (s *Server) apiServerInstancesUpdateLabel(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	localName := r.PathValue("name")
	var req apiServerInstanceLabelReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.store.UpdateServerInstanceLabel(r.Context(), serverID, localName, strings.TrimSpace(req.Label)); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, msg(r, "unknown instance", "неизвестный провайдер"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "server_instance.label", serverID+"/"+localName)
	writeOK(w, nil)
}

type apiServerInstanceDescriptionReq struct {
	Description string `json:"description"`
}

// PUT /api/servers/{id}/instances/{name}/description — set an existing
// instance's admin note (shown to portal users alongside the label).
func (s *Server) apiServerInstancesUpdateDescription(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	localName := r.PathValue("name")
	var req apiServerInstanceDescriptionReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.store.UpdateServerInstanceDescription(r.Context(), serverID, localName, strings.TrimSpace(req.Description)); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, msg(r, "unknown instance", "неизвестный провайдер"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "server_instance.description", serverID+"/"+localName)
	writeOK(w, nil)
}

type apiServerInstanceVisibilityReq struct {
	Visible bool `json:"visible"`
}

// PUT /api/servers/{id}/instances/{name}/visibility — whether this instance
// can be requested/seen at all in the self-service portal.
func (s *Server) apiServerInstancesUpdateVisibility(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	localName := r.PathValue("name")
	var req apiServerInstanceVisibilityReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.store.UpdateServerInstanceVisibility(r.Context(), serverID, localName, req.Visible); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, msg(r, "unknown instance", "неизвестный провайдер"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "server_instance.visibility", serverID+"/"+localName)
	writeOK(w, nil)
}

// DELETE /api/servers/{id}/instances/{name} — unregisters the instance from
// the panel only; does NOT uninstall the software or touch its config files
// on the host (same caution as deleting a server).
func (s *Server) apiServerInstancesDelete(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	localName := r.PathValue("name")
	if err := s.store.DeleteServerInstance(r.Context(), serverID, localName); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "server_instance.delete", serverID+"/"+localName)
	if s.mgr != nil {
		if err := s.mgr.Rebuild(r.Context(), serverID); err != nil {
			writeOKMsg(w, msgf(r, "instance removed, but re-registering the server failed: %v", "провайдер удалён, но повторно зарегистрировать сервер не удалось: %v", err), nil)
			return
		}
	}
	writeOK(w, nil)
}
