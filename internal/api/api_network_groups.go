package api

import "net/http"

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
