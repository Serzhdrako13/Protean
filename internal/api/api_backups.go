package api

import (
	"net/http"
	"strconv"

	"protean/internal/vpn"
)

type apiBackup struct {
	ID      int64  `json:"id"`
	SavedAt string `json:"saved_at"`
	Bytes   int    `json:"bytes"`
	Preview string `json:"preview"`
}

// GET /api/providers/{provider}/backups — wg-family config-file backups
// (backlog item 3).
func (s *Server) apiBackupsList(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if !s.instanceExists(providerName) {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	rows, err := s.store.ListConfBackups(r.Context(), providerName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiBackup, 0, len(rows))
	for _, b := range rows {
		preview := b.Content
		if len(preview) > 200 {
			preview = preview[:200] + "…"
		}
		out = append(out, apiBackup{ID: b.ID, SavedAt: b.SavedAt.Format("2006-01-02 15:04:05"), Bytes: len(b.Content), Preview: preview})
	}
	writeOK(w, out)
}

// POST /api/providers/{provider}/backups/{id}/restore
func (s *Server) apiRestoreBackup(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	restorer, ok := prov.(vpn.ConfRestorer)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "provider does not support config restore", "провайдер не поддерживает восстановление конфигурации"))
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	backup, err := s.store.GetConfBackup(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if backup.Provider != providerName {
		writeErr(w, http.StatusBadRequest, msg(r, "backup does not belong to this provider", "резервная копия не принадлежит этому провайдеру"))
		return
	}
	if err := restorer.RestoreConf(r.Context(), backup.Content); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "conf.restore", providerName+"/backup#"+strconv.FormatInt(id, 10))
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}
