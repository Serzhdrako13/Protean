package api

import (
	"fmt"
	"net/http"

	"protean/zabbix"
)

var zabbixTemplateFiles = map[string]string{
	"7.4": "protean-zabbix-7.4.yaml",
	"8.0": "protean-zabbix-8.0.yaml",
}

// GET /api/zabbix/template?version=7.4|8.0 -- serves the matching
// ready-to-import Zabbix template (see zabbix/README.md), embedded into the
// binary at build time (zabbix/embed.go). Admin-only by virtue of not being
// under portalRoleAllowedPrefixes, same as every other admin-only route.
func (s *Server) apiZabbixTemplateDownload(w http.ResponseWriter, r *http.Request) {
	version := r.URL.Query().Get("version")
	filename, ok := zabbixTemplateFiles[version]
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "unknown Zabbix template version", "неизвестная версия шаблона Zabbix"))
		return
	}
	b, err := zabbix.FS.ReadFile(filename)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write(b)
}
