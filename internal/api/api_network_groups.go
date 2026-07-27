package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"protean/internal/store"
)

type apiNetworkGroup struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// GET /api/network-groups -- feeds the group picker Select on the Subnets
// page and a provider instance's mesh settings.
func (s *Server) apiNetworkGroupsList(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListNetworkGroups(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiNetworkGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, apiNetworkGroup{ID: g.ID, Name: g.Name})
	}
	writeOK(w, out)
}

type apiNetworkGroupRenameReq struct {
	Name string `json:"name"`
}

// PUT /api/network-groups/{id} -- rename a group (e.g. an admin renaming
// an auto-generated "Сеть 1" to something meaningful once they know what
// it actually is). Auto-naming during detection/mesh-linking always
// leaves a group renameable afterward -- it's never a dead-end label.
func (s *Server) apiNetworkGroupsRename(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiNetworkGroupRenameReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "name is required", "укажите название"))
		return
	}
	g, err := s.store.RenameNetworkGroup(r.Context(), id, name)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	if store.IsUniqueViolation(err) {
		writeErr(w, http.StatusBadRequest, msg(r, "a group with this name already exists", "группа с таким названием уже существует"))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "network_group.rename", g.Name)
	writeOK(w, apiNetworkGroup{ID: g.ID, Name: g.Name})
}
