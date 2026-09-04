package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"protean/internal/store"
	"protean/internal/vpn"
	"protean/internal/vpn/amneziawg"
)

// instanceMeshCapable reports whether an instance's type can join the mesh.
func (s *Server) instanceMeshCapable(id string) bool {
	prov, ok := s.reg.Get(id)
	return ok && meshCapableTypes[prov.Type()]
}

type apiServerConfig struct {
	ListenPort int    `json:"listen_port"`
	Address    string `json:"address"`
	DNS        string `json:"dns"`
	// MTU: 0 = not set (OS/wg-quick/OpenVPN default).
	MTU int `json:"mtu"`
	// Mssfix: OpenVPN-only (tun-mtu's sibling, clamps TCP MSS instead of the
	// tunnel device MTU). 0 = not set. Ignored for every other provider type.
	Mssfix int               `json:"mssfix,omitempty"`
	Extra  map[string]string `json:"extra,omitempty"`
}

// GET /api/providers/{provider}/server-config — wg-family listen port/
// address/DNS/AmneziaWG obfuscation params (backlog item 1).
func (s *Server) apiServerConfigGet(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	status, err := prov.Status(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := apiServerConfig{ListenPort: status.ListenPort, Address: status.Address, DNS: status.DNS, MTU: status.MTU}
	if prov.Type() == "amneziawg" {
		cfg.Extra = map[string]string{}
		for _, k := range amneziawg.ObfuscationKeys {
			cfg.Extra[k] = status.Extra[k]
		}
	}
	if prov.Type() == "openvpn" {
		cfg.Mssfix = status.Mssfix
	}
	writeOK(w, cfg)
}

// PUT /api/providers/{provider}/server-config
func (s *Server) apiServerConfigUpdate(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	var req apiServerConfig
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "неверное тело запроса"))
		return
	}

	// OpenVPN has no live server-config edit path the way wg-family does
	// (see openvpn.Provider.UpdateServerConfig's stub) -- its conf is only
	// ever fully re-rendered by EnsureServer from Options set at provider-
	// construction time, so mtu/mssfix go through persist-then-rebuild-then-
	// reprovision instead of the generic UpdateServerConfig call below.
	if prov.Type() == "openvpn" {
		saved, applyErr := s.updateOpenVPNMTU(r.Context(), providerName, req.MTU, req.Mssfix)
		if !saved {
			writeErr(w, http.StatusInternalServerError, applyErr.Error())
			return
		}
		s.audit(r.Context(), "server.update", providerName)
		s.invalidateStatus(providerName)
		s.touchInstanceConfig(r.Context(), providerName)
		// The value is saved regardless of apply outcome -- it'll take on
		// the next successful re-provision (e.g. once the host actually has
		// OpenVPN running), same "saved but apply failed" softness
		// apiMeshSettingsUpdate already uses for cert-based providers.
		if applyErr != nil {
			writeJSON(w, http.StatusOK, apiEnvelope{Success: false, Msg: msgf(r, "settings saved, but applying failed: %v", "настройки сохранены, но применение не удалось: %v", applyErr)})
			return
		}
		writeOK(w, nil)
		return
	}

	// Subnet/mask is fixed at creation time -- changing it later can strand
	// already-issued peers outside the new range, so the settings page (and
	// this endpoint) only ever let it be read back, never edited. The
	// frontend already disables the field; this is the actual enforcement.
	if current, err := prov.Status(r.Context()); err == nil {
		if want := strings.TrimSpace(req.Address); want != "" && want != current.Address {
			writeErr(w, http.StatusBadRequest, msg(r, "the subnet address can't be changed after creation", "адрес подсети нельзя изменить после создания"))
			return
		}
	}

	cfg := vpn.ServerConfig{
		ListenPort: req.ListenPort, Address: strings.TrimSpace(req.Address), DNS: strings.TrimSpace(req.DNS),
		MTU: req.MTU, Extra: map[string]string{},
	}
	if prov.Type() == "amneziawg" {
		for _, k := range amneziawg.ObfuscationKeys {
			if v := strings.TrimSpace(req.Extra[k]); v != "" {
				cfg.Extra[k] = v
			}
		}
	}
	if err := prov.UpdateServerConfig(r.Context(), cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "server.update", providerName)
	s.invalidateStatus(providerName)
	s.touchInstanceConfig(r.Context(), providerName)
	writeOK(w, nil)
}

// touchInstanceConfig bumps the instance's config_changed_at so the portal
// can flag existing peer downloads as stale (see store.TouchServerInstanceConfig).
// Best-effort: a failure here shouldn't fail a config update that already
// applied successfully, just log it.
func (s *Server) touchInstanceConfig(ctx context.Context, providerName string) {
	if s.store == nil {
		return
	}
	if err := s.store.TouchServerInstanceConfig(ctx, serverPart(providerName), localName(providerName)); err != nil {
		slog.Warn("touch instance config_changed_at failed", "provider", providerName, "err", err)
	}
}

// updateOpenVPNMTU persists tun-mtu/mssfix into the instance's Config map
// and hot-applies it: rebuild the provider (so it picks up the new Options
// from Config) then re-provision (rewrites the on-host .conf via
// EnsureServer and restarts the service) -- the same two steps
// apiServerInstancesCreate/apiMeshSettingsUpdate already rely on separately,
// just chained together here for this one settings change. saved reports
// whether the value made it to the DB at all (a false here is a real
// error -- nothing to fall back on); once saved=true, a non-nil error is
// just "didn't apply live yet" and the caller should respond 200 with a
// soft warning, not fail the request.
func (s *Server) updateOpenVPNMTU(ctx context.Context, providerName string, mtu, mssfix int) (saved bool, err error) {
	patch := map[string]string{"mtu": "", "mssfix": ""}
	if mtu > 0 {
		patch["mtu"] = strconv.Itoa(mtu)
	}
	if mssfix > 0 {
		patch["mssfix"] = strconv.Itoa(mssfix)
	}
	serverID := serverPart(providerName)
	if err := s.store.UpdateServerInstanceConfig(ctx, serverID, localName(providerName), patch); err != nil {
		return false, fmt.Errorf("save config: %w", err)
	}
	if s.mgr == nil {
		return true, fmt.Errorf("server manager not wired")
	}
	if err := s.mgr.Rebuild(ctx, serverID); err != nil {
		return true, fmt.Errorf("rebuild provider: %w", err)
	}
	return true, s.provisionCert(ctx, providerName)
}

type apiMeshSettings struct {
	MeshEnabled     bool   `json:"mesh_enabled"`
	InternetEgress  bool   `json:"internet_egress"`
	AutoAssignStart string `json:"auto_assign_start,omitempty"`
	AutoAssignEnd   string `json:"auto_assign_end,omitempty"`
	MeshCapable     bool   `json:"mesh_capable"`
	ServiceUnit     string `json:"service_unit,omitempty"`
	ServiceStatus   string `json:"service_status,omitempty"`
	// GroupID/GroupName: this instance's network group, if any.
	// NewGroupName is PUT-only (create-on-the-fly), ignored on GET.
	GroupID      *int64 `json:"group_id,omitempty"`
	GroupName    string `json:"group_name,omitempty"`
	NewGroupName string `json:"new_group_name,omitempty"`
}

func (s *Server) buildAPIMeshSettings(r *http.Request, providerName string) (apiMeshSettings, error) {
	out := apiMeshSettings{MeshCapable: s.instanceMeshCapable(providerName)}
	ps, err := s.store.GetProviderSettings(r.Context(), providerName)
	if err != nil {
		return out, err
	}
	out.MeshEnabled = ps.MeshEnabled
	out.InternetEgress = ps.InternetEgress
	out.AutoAssignStart = ps.AutoAssignStart
	out.AutoAssignEnd = ps.AutoAssignEnd
	out.GroupID = ps.GroupID
	out.GroupName = s.groupName(r.Context(), ps.GroupID)
	if prov, ok := s.reg.Get(providerName); ok {
		if sn, ok := prov.(vpn.ServiceNamed); ok {
			out.ServiceUnit = sn.ServiceName()
			if inst, ok := s.installerForProvider(providerName); ok {
				if st, err := inst.ServiceStatus(r.Context(), out.ServiceUnit); err == nil {
					out.ServiceStatus = st
				}
			}
		}
	}
	return out, nil
}

// GET /api/providers/{provider}/mesh-settings
func (s *Server) apiMeshSettingsGet(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if !s.instanceExists(providerName) {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	out, err := s.buildAPIMeshSettings(r, providerName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, out)
}

// PUT /api/providers/{provider}/mesh-settings — saves mesh_enabled/
// internet_egress, then hot-applies (re-provision for cert-based, host
// networking for wg-family) so the change takes effect without a separate
// "Set up" step.
func (s *Server) apiMeshSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	var req apiMeshSettings
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "неверное тело запроса"))
		return
	}
	if req.AutoAssignStart != "" && net.ParseIP(req.AutoAssignStart) == nil {
		writeErr(w, http.StatusBadRequest, msg(r, "invalid auto-assign range start", "неверный начальный адрес диапазона авто-выдачи"))
		return
	}
	if req.AutoAssignEnd != "" && net.ParseIP(req.AutoAssignEnd) == nil {
		writeErr(w, http.StatusBadRequest, msg(r, "invalid auto-assign range end", "неверный конечный адрес диапазона авто-выдачи"))
		return
	}
	prev, err := s.store.GetProviderSettings(r.Context(), providerName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetProviderSettings(r.Context(), store.ProviderSettings{
		Provider: providerName, MeshEnabled: req.MeshEnabled, InternetEgress: req.InternetEgress,
		AutoAssignStart: req.AutoAssignStart, AutoAssignEnd: req.AutoAssignEnd,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The GET response always echoes group_id/group_name back, so the
	// frontend always resubmits the current-or-changed desired group
	// state on every save here -- safe to always persist, same as
	// mesh_enabled/internet_egress just above (no "did it change" guard
	// needed; nil unambiguously means "no group").
	groupID, err := s.resolveGroupID(r.Context(), req.GroupID, req.NewGroupName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := s.store.SetProviderGroup(r.Context(), providerName, groupID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	_, certBased := prov.(vpn.ClientConfigProvider)
	changed := req.MeshEnabled != prev.MeshEnabled || req.InternetEgress != prev.InternetEgress
	var applyErr error
	switch {
	case certBased && changed:
		applyErr = s.provisionCert(r.Context(), providerName)
	case !certBased && req.InternetEgress != prev.InternetEgress:
		if nc, ok := prov.(vpn.NetworkController); ok {
			if err := nc.ApplyNetworking(r.Context(), req.InternetEgress); err != nil {
				applyErr = err
			} else {
				s.invalidateStatus(providerName)
			}
		}
	}
	s.audit(r.Context(), "network.update", providerName)

	// Turning on mesh/egress routes traffic THROUGH this host -- re-check
	// net.ipv4.ip_forward every time rather than trusting it was set once
	// during the interactive setup-host.sh bootstrap: a reboot without the
	// sysctl.d drop-in surviving, or the value flipped back out-of-band,
	// would otherwise silently break routing until someone noticed.
	turningOn := (req.MeshEnabled && !prev.MeshEnabled) || (req.InternetEgress && !prev.InternetEgress)
	var ipForwardErr error
	if turningOn {
		if inst, ok := s.installerForProvider(providerName); ok {
			if err := inst.EnsureIPForward(r.Context()); err != nil {
				slog.Error("ensure ip_forward failed", "provider", providerName, "err", err)
				ipForwardErr = err
			} else {
				s.audit(r.Context(), "server.ip_forward_enabled", providerName)
			}
		}
	}

	out, _ := s.buildAPIMeshSettings(r, providerName)
	if applyErr != nil {
		writeJSON(w, http.StatusOK, apiEnvelope{Success: false, Msg: msgf(r, "settings saved, but applying failed: %v", "настройки сохранены, но применение не удалось: %v", applyErr), Obj: out})
		return
	}
	// Before this, a failure here was logged only -- the UI reported plain
	// success while the feature's core precondition (traffic can't route
	// between sites/egress without ip_forward) silently didn't hold,
	// discoverable only by reading container logs.
	if ipForwardErr != nil {
		writeJSON(w, http.StatusOK, apiEnvelope{Success: false, Msg: msgf(r,
			"settings saved, but enabling IPv4 forwarding on the host failed -- traffic will not route between sites: %v",
			"настройки сохранены, но включить IPv4-форвардинг на хосте не удалось — трафик между сайтами не пойдёт: %v",
			ipForwardErr), Obj: out})
		return
	}
	writeOK(w, out)
}

type apiServiceActionReq struct {
	Action string `json:"action"`
}

// POST /api/providers/{provider}/service — restart/start/stop the provider's
// systemd unit (backlog item 4).
func (s *Server) apiServiceAction(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	sn, ok := prov.(vpn.ServiceNamed)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "provider has no service to control", "у провайдера нет управляемой службы"))
		return
	}
	var req apiServiceActionReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "неверное тело запроса"))
		return
	}
	inst, ok := s.installerForProvider(providerName)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "no installer for this server", "для этого сервера нет установщика"))
		return
	}
	if _, err := inst.Service(r.Context(), req.Action, sn.ServiceName()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Any action that STOPS the unit can silently revoke the panel's own
	// read access to a wg-family conf file (SaveConfig=true rewrites it
	// root:root 0600 on every stop) -- not just "restart": "stop" stops
	// it directly, and this codebase's own cmd_service maps "disable" to
	// `systemctl disable --now`, which also stops it. "start"/"enable"
	// alone never stop a running unit, so they're not included. This is
	// the SAME guard wgfamily.Provider's own internal restart() already
	// has, but reached here through a completely separate path (the
	// generic service-control action, not EnableForwarding/
	// ApplyNetworking/etc), so it needs its own call.
	switch req.Action {
	case "restart", "stop", "disable":
		if cpr, ok := prov.(vpn.ConfPermsRestorer); ok {
			if err := cpr.RestoreConfPerms(r.Context()); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	s.audit(r.Context(), "service."+req.Action, providerName)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}

type apiServiceLogs struct {
	Logs string `json:"logs"`
}

// GET /api/providers/{provider}/logs?lines= — last N lines of the provider's
// systemd journal, so an admin can check what happened without opening an
// SSH session (backlog item 10).
func (s *Server) apiServiceLogsGet(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	sn, ok := prov.(vpn.ServiceNamed)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "provider has no service to control", "у провайдера нет управляемой службы"))
		return
	}
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	inst, ok := s.installerForProvider(providerName)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "no installer for this server", "для этого сервера нет установщика"))
		return
	}
	out, err := inst.ServiceLogs(r.Context(), sn.ServiceName(), lines)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiServiceLogs{Logs: out})
}
