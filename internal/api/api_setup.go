package api

import "net/http"

// POST /api/providers/{provider}/setup — JSON twin of handleProviderSetup
// (handlers_setup.go): (re)provisions a certificate-based provider
// (OpenVPN/IKEv2) — CA, certs, config, service — from its current
// settings, OR (a first-time-only, no-op-if-already-done bring-up) a
// WireGuard/AmneziaWG instance's interface from its stored Config.
func (s *Server) apiProviderSetup(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	var err error
	switch prov.Type() {
	case "wireguard", "amneziawg":
		err = s.provisionWGFamily(r.Context(), providerName)
	default:
		err = s.provisionCert(r.Context(), providerName)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "provider.setup", providerName)
	writeOK(w, nil)
}
