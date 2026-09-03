package api

import (
	"net/http"
	"strings"

	"protean/internal/vpn"
)

type apiPeerForwardRulesResp struct {
	Destinations []string `json:"destinations"`
}

type apiPeerForwardRulesReq struct {
	Destinations []string `json:"destinations"`
}

// peerAddressIsStable reports whether a provider assigns each peer a
// fixed tunnel address that survives reconnects -- true for wg-family
// (config-assigned) and OpenVPN (CCD ifconfig-push keyed by CN), false
// for IKEv2 (pool-assigned per session, only knowable live via
// swanctl --list-sas) and xray (no routed-subnet/FORWARD concept at all).
// A per-peer FORWARD rule keyed to an address that can change on the next
// reconnect would silently stop matching -- or start matching a
// DIFFERENT client that later got the same pool address -- so this is a
// hard refusal, not a "works most of the time" best-effort.
func peerAddressIsStable(providerType string) bool {
	switch providerType {
	case "wireguard", "amneziawg", "openvpn":
		return true
	default:
		return false
	}
}

// peerTunnelAddress finds a peer's own stable address (first AllowedIPs
// entry, matching handlers_peers.go's own "own address is index 0"
// convention) by its raw public key/identifier.
func peerTunnelAddress(peers []vpn.Peer, pubkey string) (string, bool) {
	for _, p := range peers {
		if p.PublicKey == pubkey && len(p.AllowedIPs) > 0 {
			return p.AllowedIPs[0], true
		}
	}
	return "", false
}

// GET /api/providers/{provider}/peers/{id}/allowed-destinations
func (s *Server) apiPeerForwardRulesGet(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if _, err := decodePeerID(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "peer not found", "клиент не найден"))
		return
	}
	dests, err := s.store.ListPeerForwardRules(r.Context(), providerName, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if dests == nil {
		dests = []string{}
	}
	writeOK(w, apiPeerForwardRulesResp{Destinations: dests})
}

// PUT /api/providers/{provider}/peers/{id}/allowed-destinations -- full
// replace. Applies the host iptables rules BEFORE persisting: a host-apply
// failure must never leave a DB record claiming a restriction that was
// never actually enforced.
func (s *Server) apiPeerForwardRulesPut(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	pubkey, err := decodePeerID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "peer not found", "клиент не найден"))
		return
	}
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	if !peerAddressIsStable(prov.Type()) {
		writeErr(w, http.StatusBadRequest, msg(r,
			"this provider type assigns client addresses dynamically per connection; a stable per-client rule isn't possible yet",
			"этот тип провайдера назначает адрес клиента динамически при каждом подключении — устойчивое правило для конкретного клиента пока невозможно"))
		return
	}

	var req apiPeerForwardRulesReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	dests := make([]string, 0, len(req.Destinations))
	for _, d := range req.Destinations {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		dests = append(dests, d)
	}

	peers, err := s.providerPeers(r.Context(), prov)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	addr, ok := peerTunnelAddress(peers, pubkey)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r,
			"cannot resolve this peer's tunnel address (server may be down)",
			"не удалось определить туннельный адрес клиента (сервер может быть недоступен)"))
		return
	}

	inst, ok := s.installerForProvider(providerName)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "server manager not configured", "менеджер серверов не настроен"))
		return
	}
	if err := inst.SetPeerForwardRules(r.Context(), addr, dests); err != nil {
		writeErr(w, http.StatusBadGateway, msgf(r, "applying the host rules failed: %v", "не удалось применить правила на хосте: %v", err))
		return
	}

	if err := s.store.SetPeerForwardRules(r.Context(), providerName, r.PathValue("id"), dests); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "peer.forward_rules.update", providerName+"/"+pubkey)
	writeOK(w, apiPeerForwardRulesResp{Destinations: dests})
}
