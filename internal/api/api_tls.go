package api

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

var validTLSMode = map[string]bool{"self_signed": true, "acme": true, "manual": true, "proxy": true}

// apiTLSSettings mirrors store.TLSState but never round-trips the sealed
// manual key blob -- ManualKeyPEM is write-only (accepted on PUT, never
// echoed back on GET); ManualHasKey tells the UI whether a key is already
// stored without exposing it.
type apiTLSSettings struct {
	Mode string `json:"mode"`

	SSKeyAlgo         string `json:"ss_key_algo"`
	SSValidityDays    int    `json:"ss_validity_days"`
	SSRenewBeforeDays int    `json:"ss_renew_before_days"`
	SSSans            string `json:"ss_sans"`

	AcmeDirectoryURL string `json:"acme_directory_url"`
	AcmeDomains      string `json:"acme_domains"`
	AcmeEmail        string `json:"acme_email"`
	AcmeChallenge    string `json:"acme_challenge"`
	AcmeTrustRootPEM string `json:"acme_trust_root_pem,omitempty"`

	ManualCertPEM string `json:"manual_cert_pem,omitempty"`
	ManualKeyPEM  string `json:"manual_key_pem,omitempty"`
	ManualHasKey  bool   `json:"manual_has_key"`
}

type apiTLSStatus struct {
	Mode                string    `json:"mode"`
	SelfSignedExpiresAt time.Time `json:"self_signed_expires_at,omitempty"`
	LastServed          string    `json:"last_served"`
	LastError           string    `json:"last_error,omitempty"`
	Degraded            bool      `json:"degraded"`
}

type apiTLSResponse struct {
	Settings apiTLSSettings `json:"settings"`
	Status   apiTLSStatus   `json:"status"`
}

// GET /api/tls
func (s *Server) apiTLSGet(w http.ResponseWriter, r *http.Request) {
	if s.tlsMgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "tls manager not wired", "TLS-менеджер не подключён"))
		return
	}
	state, err := s.store.GetTLSState(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	status := s.tlsMgr.GetStatus()
	writeOK(w, apiTLSResponse{
		Settings: apiTLSSettings{
			Mode:              state.Mode,
			SSKeyAlgo:         state.SSKeyAlgo,
			SSValidityDays:    state.SSValidityDays,
			SSRenewBeforeDays: state.SSRenewBeforeDays,
			SSSans:            state.SSSans,
			AcmeDirectoryURL:  state.AcmeDirectoryURL,
			AcmeDomains:       state.AcmeDomains,
			AcmeEmail:         state.AcmeEmail,
			AcmeChallenge:     state.AcmeChallenge,
			AcmeTrustRootPEM:  state.AcmeTrustRootPEM,
			ManualCertPEM:     state.ManualCertPEM,
			ManualHasKey:      len(state.ManualKeyEnc) > 0,
		},
		Status: apiTLSStatus{
			Mode: status.Mode, SelfSignedExpiresAt: status.SelfSignedExpiresAt,
			LastServed: status.LastServed, LastError: status.LastError, Degraded: status.Degraded,
		},
	})
}

// PUT /api/tls -- switches mode and/or updates the active mode's settings.
// Always re-issues the self-signed fallback inline (cheap, local); ACME
// issuance itself happens lazily on the next handshake (needs a real
// challenge round-trip, not something to block this response on).
func (s *Server) apiTLSUpdate(w http.ResponseWriter, r *http.Request) {
	if s.tlsMgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "tls manager not wired", "TLS-менеджер не подключён"))
		return
	}
	var req apiTLSSettings
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if !validTLSMode[req.Mode] {
		writeErr(w, http.StatusBadRequest, msg(r, "unknown mode", "неизвестный режим"))
		return
	}
	existing, err := s.store.GetTLSState(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Start from the existing state and only overwrite the group of fields
	// that belongs to the mode actually being saved. The frontend's Form
	// only mounts one mode's Form.Items at a time (self_signed/acme/manual
	// sections are conditionally rendered), so req's OTHER groups arrive
	// as Go zero values -- not real data. Building newState from req
	// directly (the old behavior) meant saving in acme mode wrote empty
	// strings over ss_sans/ss_key_algo/etc, and saving in self_signed mode
	// wiped every acme_* field -- degrading self-signed's role as a
	// permanent fallback regardless of which mode is actually active, and
	// destroying ACME settings an admin would need again after a debug
	// detour through another mode. Manual's cert/key are handled by their
	// own dedicated block below (already correct: only overwritten when a
	// new key is actually uploaded).
	newState := existing
	newState.Mode = req.Mode
	switch req.Mode {
	case "self_signed":
		newState.SSKeyAlgo = req.SSKeyAlgo
		newState.SSValidityDays = req.SSValidityDays
		newState.SSRenewBeforeDays = req.SSRenewBeforeDays
		newState.SSSans = strings.TrimSpace(req.SSSans)
	case "acme":
		newState.AcmeDirectoryURL = strings.TrimSpace(req.AcmeDirectoryURL)
		newState.AcmeDomains = strings.TrimSpace(req.AcmeDomains)
		newState.AcmeEmail = strings.TrimSpace(req.AcmeEmail)
		newState.AcmeChallenge = req.AcmeChallenge
		newState.AcmeTrustRootPEM = req.AcmeTrustRootPEM
	}
	if newState.SSKeyAlgo == "" {
		newState.SSKeyAlgo = "ecdsa_p256"
	}
	if newState.SSValidityDays <= 0 {
		newState.SSValidityDays = 397
	}
	if newState.SSRenewBeforeDays <= 0 {
		newState.SSRenewBeforeDays = 30
	}
	if newState.AcmeChallenge == "" {
		newState.AcmeChallenge = "tls-alpn-01"
	}

	if req.Mode == "manual" {
		if req.ManualKeyPEM != "" {
			if req.ManualCertPEM == "" {
				writeErr(w, http.StatusBadRequest, msg(r, "manual mode needs both certificate and key PEM", "для ручного режима нужны и сертификат, и ключ в формате PEM"))
				return
			}
			if _, err := tls.X509KeyPair([]byte(req.ManualCertPEM), []byte(req.ManualKeyPEM)); err != nil {
				writeErr(w, http.StatusBadRequest, msgf(r, "certificate/key don't match or are invalid: %s", "сертификат и ключ не совпадают или недействительны: %s", err.Error()))
				return
			}
			sealed, err := s.enc.Seal(req.ManualKeyPEM)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			newState.ManualCertPEM = req.ManualCertPEM
			newState.ManualKeyEnc = sealed
		} else if existing.ManualCertPEM == "" {
			writeErr(w, http.StatusBadRequest, msg(r, "no manual certificate uploaded yet -- provide manual_cert_pem and manual_key_pem", "сертификат ещё не загружен -- укажите manual_cert_pem и manual_key_pem"))
			return
		}
	}
	if req.Mode == "acme" && newState.AcmeDomains == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "acme mode needs at least one domain", "для режима acme нужен хотя бы один домен"))
		return
	}

	if err := s.tlsMgr.Apply(r.Context(), newState); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "tls.update", req.Mode)

	// Switching to/from "proxy" changes whether the process's listener
	// terminates TLS at all -- something that can't be hot-swapped on a
	// running http.Server (unlike self_signed/acme/manual, which just swap
	// GetCertificate's behavior and apply immediately). Say so plainly
	// instead of leaving the admin wondering why nothing changed yet.
	if req.Mode == "proxy" || existing.Mode == "proxy" {
		writeOKMsg(w, msg(r, "saved -- switching between \"behind proxy\" and other modes takes effect only after the panel container restarts", "сохранено — переключение между «за прокси» и остальными режимами применяется только после перезапуска контейнера панели"), nil)
		return
	}
	writeOK(w, nil)
}

// POST /api/tls/self-signed/reissue -- forces a fresh self-signed leaf
// under the existing (permanent) CA using the currently saved settings,
// without waiting for the background renew loop -- e.g. right after
// changing SANs/key algo/validity.
func (s *Server) apiTLSReissueSelfSigned(w http.ResponseWriter, r *http.Request) {
	if s.tlsMgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "tls manager not wired", "TLS-менеджер не подключён"))
		return
	}
	if err := s.tlsMgr.ReissueSelfSigned(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "tls.self_signed.reissue", "")
	writeOK(w, nil)
}
