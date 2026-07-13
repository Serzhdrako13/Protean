package api

import (
	"net/http"
	"sort"
)

// managedProviders are the ones the panel can fully operate once installed
// (wg-family). OpenVPN/IKEv2 can be installed from here but aren't managed.
var managedProviders = map[string]bool{"wireguard": true, "amneziawg": true}

// resolveServer picks the target server for host-level actions (install/detect):
// the `server` query/form value if valid, else the first known server.
func (s *Server) resolveServer(r *http.Request) string {
	want := r.FormValue("server")
	ids := s.serverIDs()
	for _, id := range ids {
		if id == want {
			return id
		}
	}
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// serverIDs returns the known server ids (from the SSH client set), sorted.
func (s *Server) serverIDs() []string {
	var ids []string
	for id := range s.hostSet() {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
