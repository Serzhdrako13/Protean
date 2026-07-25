package api

import (
	"errors"
	"net/http"
)

type apiNetworkDetectionResponse struct {
	Provider   string         `json:"provider"`
	TunnelCIDR string         `json:"tunnel_cidr,omitempty"`
	Items      []DetectedItem `json:"items"`
}

// GET /api/providers/{provider}/network-detection — read-only preview of
// what adopting this wg-family instance's peers would classify as (see
// detectNetworkStructure). Safe to call repeatedly / poll for a refresh;
// no side effects, no confirmation needed.
func (s *Server) apiNetworkDetectionPreview(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	items, tunnelCIDR, err := s.detectNetworkStructure(r.Context(), providerName)
	if err != nil {
		switch {
		case errors.Is(err, errUnknownProvider):
			writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		case errors.Is(err, errNotWGFamily):
			writeErr(w, http.StatusBadRequest, msg(r, "network detection is only available for WireGuard/AmneziaWG instances", "обнаружение структуры сети доступно только для инстансов WireGuard/AmneziaWG"))
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	if items == nil {
		items = []DetectedItem{}
	}
	writeOK(w, apiNetworkDetectionResponse{Provider: providerName, TunnelCIDR: tunnelCIDR, Items: items})
}
