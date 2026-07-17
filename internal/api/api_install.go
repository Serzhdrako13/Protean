package api

import "net/http"

type apiProviderInstall struct {
	Name          string `json:"name"`
	Label         string `json:"label"`
	Managed       bool   `json:"managed"`
	Installed     bool   `json:"installed"`
	Installable   bool   `json:"installable"`
	ServiceActive bool   `json:"service_active"`
	ConfigExists  bool   `json:"config_exists"`
}

type apiInstallStatus struct {
	ServerID    string               `json:"server_id"`
	Servers     []string             `json:"servers"`
	HostPretty  string               `json:"host_pretty"`
	PkgManager  string               `json:"pkg_manager"`
	Systemd     bool                 `json:"systemd"`
	Supported   bool                 `json:"supported"`
	DetectError string               `json:"detect_error,omitempty"`
	Providers   []apiProviderInstall `json:"providers"`
}

func (s *Server) buildInstallStatus(r *http.Request, serverID string) apiInstallStatus {
	out := apiInstallStatus{ServerID: serverID, Servers: s.serverIDs()}

	inst, ok := s.installerForProvider(serverID + ":")
	if !ok {
		out.DetectError = "no server selected or server unavailable"
		return out
	}
	info, err := inst.Detect(r.Context())
	if err != nil {
		out.DetectError = err.Error()
	} else {
		out.HostPretty = info.PrettyName
		out.PkgManager = info.PkgManager
		out.Systemd = info.Systemd
		out.Supported = info.Supported
	}
	for _, p := range knownProviderTypes {
		pv := apiProviderInstall{Name: p.Name, Label: p.Label, Managed: managedProviders[p.Name]}
		if pi, ok := info.Providers[p.Name]; ok {
			pv.Installed = pi.Installed
			pv.Installable = pi.Installable
			pv.ServiceActive = pi.ServiceActive
			pv.ConfigExists = pi.ConfigExists
		}
		out.Providers = append(out.Providers, pv)
	}
	return out
}

// GET /api/install?server=<id> — detected host info + per-type install
// status, the JSON twin of buildProvidersView/handleProvidersPage
// (handlers_providers.go).
func (s *Server) apiInstallStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.buildInstallStatus(r, s.resolveServer(r)))
}

// POST /api/install/{provider}?server=<id> — runs the on-host installer for
// one provider TYPE (not an instance) and returns its output alongside the
// refreshed detect status.
func (s *Server) apiInstallProvider(w http.ResponseWriter, r *http.Request) {
	providerType := r.PathValue("provider")
	if !isKnownProviderType(providerType) {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider type", "неизвестный тип провайдера"))
		return
	}
	serverID := s.resolveServer(r)
	inst, ok := s.installerForProvider(serverID + ":")
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "no server selected", "сервер не выбран"))
		return
	}

	out, err := inst.Install(r.Context(), providerType)
	s.audit(r.Context(), "provider.install", serverID+"/"+providerType)

	status := s.buildInstallStatus(r, serverID)
	if err != nil {
		writeJSON(w, http.StatusOK, apiEnvelope{
			Success: false,
			Msg:     msgf(r, "install failed: %v", "установка не удалась: %v", err),
			Obj:     map[string]any{"output": out, "status": status},
		})
		return
	}
	writeJSON(w, http.StatusOK, apiEnvelope{
		Success: true,
		Msg:     msgf(r, "%s install finished", "%s: установка завершена", typeLabel(providerType)),
		Obj:     map[string]any{"output": out, "status": status},
	})
}
