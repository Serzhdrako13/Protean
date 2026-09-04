package api

import (
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"protean/internal/vpn"
)

// validPeerName rejects control characters (most importantly newlines) in
// a peer's display name while allowing any real-world name (Unicode
// letters/digits, spaces, and the common punctuation display names use).
// This name flows unvalidated into places that render it literally into a
// generated config file: cert-based providers set it as the client cert's
// CommonName (internal/vpn/ikev2/provider.go, internal/vpn/openvpn/
// provider.go), and ikev2/swanctl.go renders that CN as a bare `id =
// <value>` line with no escaping. A name containing a newline could
// inject arbitrary swanctl directives into the generated conf.d file.
// wg-family's own conf writer already strips \n/\r from names
// (wgfamily/conf.go), but cert-based providers had no equivalent
// guard -- fixing it once here, at the one place every peer name enters
// the system, protects every provider type instead of patching each
// consumer separately.
var validPeerName = regexp.MustCompile(`^[\p{L}\p{N} ._@-]{1,64}$`)

type apiPeerCreateReq struct {
	Name          string  `json:"name"`
	ClientAddress string  `json:"client_address"`
	Keepalive     int     `json:"keepalive"`
	ExpireDays    int     `json:"expire_days"`
	SubnetIDs     []int64 `json:"subnet_ids"`
	OwnPublicKey  string  `json:"own_public_key"`
	ClientCSR     string  `json:"client_csr"`
	Category      string  `json:"category"`
	// AccessRequestID, when set, links this newly-created peer to a portal
	// user's already-approved access request (see api_access_requests.go) —
	// this is how a cert-based/failed-auto approval gets closed out by the
	// admin's normal "add client" flow instead of a second bespoke endpoint.
	AccessRequestID int64 `json:"access_request_id,omitempty"`
}

// POST /api/providers/{provider}/peers — JSON twin of handleCreatePeer
// (handlers_peers.go); same three creation modes (own key / CSR / panel-
// generated), same secret-sealing + rollback invariant.
func (s *Server) apiCreatePeer(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	var req apiPeerCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validPeerName.MatchString(name) {
		writeErr(w, http.StatusBadRequest, msg(r, "invalid peer name", "недопустимое имя клиента"))
		return
	}
	clientAddress := strings.TrimSpace(req.ClientAddress)

	subnets, err := s.store.ListAllSubnets(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	allowedIPs := []string{clientAddress}
	wanted := map[int64]bool{}
	for _, id := range req.SubnetIDs {
		wanted[id] = true
	}
	for _, sn := range subnets {
		if wanted[sn.ID] {
			allowedIPs = append(allowedIPs, sn.CIDR)
		}
	}

	ownKey := strings.TrimSpace(req.OwnPublicKey)
	csr := strings.TrimSpace(req.ClientCSR)
	spec := vpn.PeerSpec{Name: name, AllowedIPs: allowedIPs, PersistentKeepalive: req.Keepalive}

	selfManaged := false
	var result vpn.NewPeerResult
	switch {
	case ownKey != "":
		adder, ok := prov.(vpn.ConfiguredPeerAdder)
		if !ok {
			writeErr(w, http.StatusBadRequest, msg(r, "this provider doesn't support supplying your own key", "этот провайдер не поддерживает указание собственного ключа"))
			return
		}
		if !validWGPublicKey(ownKey) {
			writeErr(w, http.StatusBadRequest, msg(r, "invalid WireGuard public key (expect base64, 32 bytes)", "неверный публичный ключ WireGuard (ожидается base64, 32 байта)"))
			return
		}
		if err := adder.AddConfiguredPeer(r.Context(), ownKey, spec); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		result = vpn.NewPeerResult{Peer: vpn.Peer{ID: ownKey, Provider: providerName, Name: name, PublicKey: ownKey, AllowedIPs: allowedIPs}}
		selfManaged = true
	case csr != "":
		signer, ok := prov.(vpn.CSRSigner)
		if !ok {
			writeErr(w, http.StatusBadRequest, msg(r, "this provider doesn't support signing a CSR", "этот провайдер не поддерживает подписание CSR"))
			return
		}
		var err error
		result, err = signer.AddPeerFromCSR(r.Context(), csr, spec)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	default:
		var err error
		result, err = prov.AddPeer(r.Context(), spec)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	_, certBased := prov.(vpn.ClientConfigProvider)
	if !certBased && !selfManaged {
		blob, sealErr := s.enc.Seal(result.PrivateKey)
		if sealErr == nil {
			sealErr = s.store.SavePeerSecret(r.Context(), providerName, result.Peer.PublicKey, blob)
		}
		if sealErr != nil {
			if rbErr := prov.RemovePeer(r.Context(), result.Peer.PublicKey); rbErr != nil {
				slog.Error("api create peer: stored-secret failure AND rollback failed; manual cleanup needed",
					"pubkey", result.Peer.PublicKey, "sealErr", sealErr, "rollbackErr", rbErr)
			}
			writeErr(w, http.StatusInternalServerError, msgf(r, "failed to store peer key: %v", "не удалось сохранить ключ клиента: %v", sealErr))
			return
		}
	}

	if req.ExpireDays > 0 {
		exp := time.Now().Add(time.Duration(req.ExpireDays) * 24 * time.Hour)
		if err := s.store.SetPeerExpiry(r.Context(), providerName, result.Peer.PublicKey, exp); err != nil {
			slog.Error("api create peer: set expiry failed", "err", err)
		}
	}
	if req.Category == "site" || req.Category == "client" {
		_ = s.store.SetPeerCategory(r.Context(), providerName, result.Peer.PublicKey, req.Category)
	}
	s.audit(r.Context(), "peer.create", providerName+"/"+name)
	s.invalidateStatus(providerName)

	urlID, _ := encodePeerID(result.Peer.PublicKey)

	if req.AccessRequestID != 0 {
		if linkMsg := s.linkPeerToAccessRequest(r, req.AccessRequestID, providerName, result.Peer.PublicKey, urlID); linkMsg != "" {
			writeOKMsg(w, linkMsg, map[string]string{"url_id": urlID})
			return
		}
	}
	writeOK(w, map[string]string{"url_id": urlID})
}

// linkPeerToAccessRequest assigns a just-created peer to the user behind an
// approved access request and runs the same sanity check the automatic path
// uses, flipping the request to granted only once that passes. Returns a
// non-empty message (to surface via writeOKMsg) when something needed the
// admin's attention; the peer itself is never rolled back here since it was
// just deliberately, manually created.
func (s *Server) linkPeerToAccessRequest(r *http.Request, requestID int64, providerName, pubkey, urlID string) string {
	ctx := r.Context()
	if pubkey == "" || urlID == "" {
		// A cert-based provider whose CA/server isn't fully provisioned yet
		// can return a peer with no real identifier (encodePeerID("") would
		// otherwise "succeed" trivially and silently grant access to a
		// peer nobody can actually use) -- exactly the "проверка, а то
		// вдруг что-то пропустил" case this check exists for.
		return msg(r, "client created, but it has no identifier (the server is probably not fully configured) — linking to the user was cancelled, check the provider", "клиент создан, но у него нет идентификатора (сервер, вероятно, не до конца настроен) — привязка к пользователю отменена, проверьте провайдера")
	}
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return msgf(r, "client created, but the access request was not found: %v", "клиент создан, но запрос доступа не найден: %v", err)
	}
	if req.Provider != providerName || req.Status == "granted" || req.Status == "denied" {
		return msg(r, "client created, but not linked: the request no longer matches (provider/status changed)", "клиент создан, но не привязан: запрос не подходит (провайдер/статус изменились)")
	}
	if err := s.store.SetPeerOwner(ctx, providerName, urlID, req.UserID); err != nil {
		return msgf(r, "client created, but failed to assign owner: %v", "клиент создан, но не удалось назначить владельца: %v", err)
	}
	if _, _, _, err := s.buildPeerDownload(ctx, providerName, pubkey, ""); err != nil {
		return msgf(r, "client created and assigned, but the configuration check failed: %v", "клиент создан и назначен, но проверка конфигурации не прошла: %v", err)
	}
	if err := s.store.SetRequestStatus(ctx, requestID, "granted"); err != nil {
		return msgf(r, "client created and assigned, but failed to update the request status: %v", "клиент создан и назначен, но не удалось обновить статус запроса: %v", err)
	}
	return ""
}

type apiPeerImportReq struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem,omitempty"`
}

// POST /api/providers/{provider}/peers/import — adopt an already-issued
// client certificate (e.g. a client from a VPN server being taken over by
// the panel) instead of issuing a new one. Only meaningful once the
// provider's CA is the one that actually signed the cert (see POST
// .../ca) -- ImportPeer itself enforces that by verifying the chain.
func (s *Server) apiImportPeer(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	importer, ok := prov.(vpn.PeerImporter)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "this provider doesn't support importing an existing certificate", "этот провайдер не поддерживает импорт существующего сертификата"))
		return
	}
	var req apiPeerImportReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	certPEM := strings.TrimSpace(req.CertPEM)
	if certPEM == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "cert_pem is required", "cert_pem обязателен"))
		return
	}
	peer, err := importer.ImportPeer(r.Context(), certPEM, strings.TrimSpace(req.KeyPEM))
	if err != nil {
		writeErr(w, http.StatusBadRequest, msgf(r, "import failed: %v", "не удалось импортировать: %v", err))
		return
	}
	s.audit(r.Context(), "peer.import", providerName+"/"+peer.Name)
	s.invalidateStatus(providerName)

	urlID, _ := encodePeerID(peer.PublicKey)
	writeOK(w, map[string]string{"url_id": urlID})
}

type apiPeerUpdateReq struct {
	Name          string  `json:"name"`
	ClientAddress string  `json:"client_address"`
	Keepalive     int     `json:"keepalive"`
	SubnetIDs     []int64 `json:"subnet_ids"`
	Category      string  `json:"category"`
}

// PUT /api/providers/{provider}/peers/{id}
func (s *Server) apiUpdatePeer(w http.ResponseWriter, r *http.Request) {
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
	var req apiPeerUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validPeerName.MatchString(name) {
		writeErr(w, http.StatusBadRequest, msg(r, "invalid peer name", "недопустимое имя клиента"))
		return
	}
	clientAddress := strings.TrimSpace(req.ClientAddress)

	subnets, err := s.store.ListAllSubnets(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The edit modal has no subnet-selection UI at all -- req.SubnetIDs is
	// always empty on every save. Rebuilding AllowedIPs purely from it
	// would silently strip any subnet CIDR this peer already routes (e.g.
	// a router peer's site subnet, adopted from an existing wg0.conf by
	// Network structure detection) on every routine name/keepalive edit.
	// Preserve whatever extra AllowedIPs entries the peer already has
	// (index 0 is always its own address, by this codebase's own
	// convention -- see handlers_peers.go/peerTunnelAddress) and only add
	// to that from req.SubnetIDs, never rebuild from scratch.
	// Fail closed, not open: if the peer list can't be read at all (the
	// most likely cause being the exact wg0.conf-permission incident this
	// preservation logic exists because of -- see the fix-conf-perms
	// commits), silently treating that as "no existing subnets" would
	// reintroduce the very bug this block fixes, and precisely when a
	// host is already in a degraded state. An admin retrying once the
	// underlying issue is fixed is a far better outcome than a second,
	// compounding data-loss event.
	peers, perr := s.providerPeers(r.Context(), prov)
	if perr != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r,
			"cannot read the current peer list, refusing to update this peer to avoid losing its existing routes: %v",
			"не удалось прочитать текущий список пиров; обновление отменено, чтобы не потерять уже настроенные маршруты пира: %v",
			perr))
		return
	}
	var existingExtra []string
	for _, p := range peers {
		if p.PublicKey == pubkey && len(p.AllowedIPs) > 1 {
			existingExtra = p.AllowedIPs[1:]
			break
		}
	}

	allowedIPs := []string{clientAddress}
	seen := map[string]bool{clientAddress: true}
	for _, cidr := range existingExtra {
		if !seen[cidr] {
			allowedIPs = append(allowedIPs, cidr)
			seen[cidr] = true
		}
	}
	wanted := map[int64]bool{}
	for _, id := range req.SubnetIDs {
		wanted[id] = true
	}
	for _, sn := range subnets {
		if wanted[sn.ID] && !seen[sn.CIDR] {
			allowedIPs = append(allowedIPs, sn.CIDR)
			seen[sn.CIDR] = true
		}
	}

	spec := vpn.PeerSpec{Name: name, AllowedIPs: allowedIPs, PersistentKeepalive: req.Keepalive}
	if err := prov.UpdatePeer(r.Context(), pubkey, spec); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Category == "site" || req.Category == "client" {
		_ = s.store.SetPeerCategory(r.Context(), providerName, pubkey, req.Category)
	}
	s.audit(r.Context(), "peer.update", providerName+"/"+name)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}

// DELETE /api/providers/{provider}/peers/{id}
func (s *Server) apiDeletePeer(w http.ResponseWriter, r *http.Request) {
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
	if err := prov.RemovePeer(r.Context(), pubkey); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeletePeerSecret(r.Context(), providerName, pubkey)
	_ = s.store.DeletePeerExpiry(r.Context(), providerName, pubkey)
	_ = s.store.DeletePeerCategory(r.Context(), providerName, pubkey)
	_ = s.store.SetPeerMuted(r.Context(), providerName, pubkey, false)
	// peer_forward_rules keys on the encoded urlID (node_peer's modern
	// convention), unlike the raw-pubkey cleanup calls above -- without
	// this, a deleted-then-recreated peer reusing the same tunnel address
	// would silently inherit a stale destination restriction.
	_ = s.store.DeletePeerForwardRules(r.Context(), providerName, r.PathValue("id"))
	s.audit(r.Context(), "peer.delete", providerName+"/"+pubkey)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}

// POST /api/providers/{provider}/peers/{id}/disable
func (s *Server) apiDisablePeer(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	pubkey, err := decodePeerID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "peer not found", "клиент не найден"))
		return
	}
	if err := s.disablePeer(r.Context(), providerName, pubkey); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "peer.disable", providerName+"/"+pubkey)
	writeOK(w, nil)
}

// POST /api/providers/{provider}/peers/{id}/enable
func (s *Server) apiEnablePeer(w http.ResponseWriter, r *http.Request) {
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
	adder, ok := prov.(vpn.ConfiguredPeerAdder)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "provider does not support enable/disable", "провайдер не поддерживает включение/отключение"))
		return
	}
	dp, err := s.store.GetDisabledPeer(r.Context(), providerName, pubkey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var allowed []string
	if dp.AllowedIPs != "" {
		allowed = strings.Split(dp.AllowedIPs, ",")
	}
	spec := vpn.PeerSpec{Name: dp.Name, AllowedIPs: allowed, PersistentKeepalive: dp.Keepalive}
	if err := adder.AddConfiguredPeer(r.Context(), pubkey, spec); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeleteDisabledPeer(r.Context(), providerName, pubkey)
	s.audit(r.Context(), "peer.enable", providerName+"/"+dp.Name)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}

// POST /api/providers/{provider}/peers/{id}/mute — toggles notification
// muting (JSON twin of handleTogglePeerMute in handlers_notify.go, which
// redirects rather than returning JSON).
func (s *Server) apiTogglePeerMute(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	pubkey, err := decodePeerID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "peer not found", "клиент не найден"))
		return
	}
	muted, err := s.store.MutedPeers(r.Context(), providerName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	next := !muted[pubkey]
	if err := s.store.SetPeerMuted(r.Context(), providerName, pubkey, next); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]bool{"muted": next})
}

// POST /api/providers/{provider}/peers/{id}/rotate
func (s *Server) apiRotatePeer(w http.ResponseWriter, r *http.Request) {
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
	rotator, ok := prov.(vpn.KeyRotator)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "provider does not support key rotation", "провайдер не поддерживает ротацию ключей"))
		return
	}
	result, err := rotator.RotatePeerKey(r.Context(), pubkey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	blob, sealErr := s.enc.Seal(result.PrivateKey)
	if sealErr == nil {
		sealErr = s.store.SavePeerSecret(r.Context(), providerName, result.Peer.PublicKey, blob)
	}
	if sealErr != nil {
		if rbErr := prov.RemovePeer(r.Context(), result.Peer.PublicKey); rbErr != nil {
			slog.Error("api rotate peer: stored-secret failure AND rollback failed; manual cleanup needed", "sealErr", sealErr, "rollbackErr", rbErr)
		}
		writeErr(w, http.StatusInternalServerError, msgf(r, "failed to store rotated key: %v", "не удалось сохранить новый ключ: %v", sealErr))
		return
	}
	if cats, err := s.store.PeerCategories(r.Context(), providerName); err == nil {
		if c := cats[pubkey]; c != "" {
			_ = s.store.SetPeerCategory(r.Context(), providerName, result.Peer.PublicKey, c)
		}
	}
	_ = s.store.DeletePeerSecret(r.Context(), providerName, pubkey)
	_ = s.store.DeletePeerCategory(r.Context(), providerName, pubkey)
	s.audit(r.Context(), "peer.rotate", providerName+"/"+result.Peer.Name)
	s.invalidateStatus(providerName)

	newID, err := encodePeerID(result.Peer.PublicKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r, "rotated but failed to encode new id: %v", "ключ повёрнут, но не удалось закодировать новый id: %v", err))
		return
	}
	writeOK(w, map[string]string{"url_id": newID})
}
