package api

import (
	"net/http"

	"protean/internal/vpnsetup"
)

// GET /api/portal/vpn-setup-content — the self-service portal's per-protocol
// "how to connect" instructions (app name/link + per-OS steps), read from a
// volume-mounted directory (see internal/vpnsetup) rather than the frontend
// bundle, so an admin can fix a stale instruction by editing a file on the
// host instead of rebuilding the panel. Language follows the same
// Accept-Language convention as everything else (see requestLang) --
// there's no query param to pick a language explicitly.
func (s *Server) apiVPNSetupContent(w http.ResponseWriter, r *http.Request) {
	b, err := vpnsetup.Load(s.vpnSetupDir, requestLang(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
