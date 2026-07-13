package api

import (
	"net/http"
	"strings"

	"protean/internal/vpn"
)

type apiCAImportReq struct {
	CACert string `json:"ca_cert"`
	CAKey  string `json:"ca_key"`
}

// POST /api/providers/{provider}/ca — import an external CA for a
// certificate-based provider (OpenVPN/IKEv2). Re-provision (setup) afterward
// so it takes effect; existing client certs must be re-issued.
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
	writeOKMsg(w, msg(r, "external CA imported — re-provision the server (Настроить сервер) so it uses the new CA; existing client certs must be re-issued", "CA импортирован — нажмите «Настроить сервер», чтобы применить новый CA; существующие клиентские сертификаты нужно перевыпустить"), nil)
}
