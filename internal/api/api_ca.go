package api

import (
	"errors"
	"net/http"
	"strings"

	"protean/internal/store"
	"protean/internal/vpn"
	"protean/internal/vpn/pki"
)

type apiCAImportReq struct {
	CACert string `json:"ca_cert"`
	CAKey  string `json:"ca_key"`
	// CRLPEM is optional: importing it alongside the CA in one step avoids
	// a window where the adopted CA is live but its revocations aren't --
	// a certificate someone already revoked on the old server would
	// otherwise briefly (or indefinitely, if the admin forgets) work again.
	CRLPEM string `json:"crl_pem,omitempty"`
}

type apiCAInfo struct {
	Configured bool   `json:"configured"`
	Source     string `json:"source,omitempty"` // "internal" | "external"
	CreatedAt  string `json:"created_at,omitempty"`
}

// GET /api/providers/{provider}/ca — current CA metadata (never the key
// material itself) so the UI can show "internal, issued <date>" vs
// "external (imported), issued <date>" without re-exposing the private key.
func (s *Server) apiCAInfo(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if _, ok := s.reg.Get(providerName); !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	m, err := s.store.GetCAMaterial(r.Context(), providerName)
	if errors.Is(err, store.ErrNotFound) {
		writeOK(w, apiCAInfo{Configured: false})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiCAInfo{Configured: true, Source: m.Source, CreatedAt: m.CreatedAt.Format("2006-01-02 15:04:05")})
}

// POST /api/providers/{provider}/ca — import an external CA (+ optionally
// its CRL) for a certificate-based provider (OpenVPN/IKEv2). Re-provision
// (setup) afterward so it takes effect; client certs issued under a
// DIFFERENT CA than the one now active must be re-issued or imported (see
// POST .../peers/import) -- importing the CRL here only carries over
// revocations, not the certs themselves.
func (s *Server) apiCAImport(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	importer, ok := prov.(vpn.CAImporter)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "provider has no importable CA", "у провайдера нет импортируемого CA"))
		return
	}
	var req apiCAImportReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	certPEM := strings.TrimSpace(req.CACert)
	keyPEM := strings.TrimSpace(req.CAKey)
	if err := importer.ImportCA(r.Context(), certPEM, keyPEM); err != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r, "import failed: %v", "не удалось импортировать: %v", err))
		return
	}
	s.audit(r.Context(), "ca.import", providerName)

	if crlPEM := strings.TrimSpace(req.CRLPEM); crlPEM != "" {
		revoked, number, err := pki.ParseCRL(crlPEM)
		if err != nil {
			// The CA import already succeeded and was audited -- a bad CRL
			// is reported but doesn't roll that back, matching this
			// endpoint's existing all-or-nothing-per-step (not
			// all-or-nothing-overall) semantics elsewhere in the app.
			writeErr(w, http.StatusBadRequest, msgf(r, "CA imported, but CRL import failed: %v", "CA импортирован, но не удалось импортировать CRL: %v", err))
			return
		}
		rows := make([]store.RevokedCertRow, 0, len(revoked))
		for _, rc := range revoked {
			rows = append(rows, store.RevokedCertRow{Serial: rc.Serial.String(), RevokedAt: rc.RevokedAt})
		}
		if err := s.store.ImportRevokedCerts(r.Context(), providerName, rows); err != nil {
			writeErr(w, http.StatusInternalServerError, msgf(r, "CA imported, but CRL import failed: %v", "CA импортирован, но не удалось импортировать CRL: %v", err))
			return
		}
		if number > 0 {
			if err := s.store.SeedCRLNumber(r.Context(), providerName, number); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		s.audit(r.Context(), "ca.crl_import", providerName)
		if rebuilder, ok := prov.(vpn.CRLRebuilder); ok {
			if err := rebuilder.RebuildCRL(r.Context()); err != nil {
				// Same softness as elsewhere: the import itself succeeded
				// and is durable in the DB; a live-apply failure (host
				// unreachable etc.) just means the next successful
				// re-provision picks it up.
				writeOKMsg(w, msgf(r, "CA and CRL imported, but applying to the host failed: %v — re-provision (Set up) to retry", "CA и CRL импортированы, но применить на хосте не удалось: %v — нажмите «Настроить сервер» чтобы повторить", err), nil)
				return
			}
		}
	}

	writeOKMsg(w, msg(r, "external CA imported — re-provision the server (Настроить сервер) so it uses the new CA; existing client certs must be re-issued or imported separately", "CA импортирован — нажмите «Настроить сервер», чтобы применить новый CA; существующие клиентские сертификаты нужно перевыпустить или импортировать отдельно"), nil)
}
