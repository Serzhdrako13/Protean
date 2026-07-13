package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"protean/internal/store"
	"protean/internal/vpn"
	"protean/internal/vpn/clientconfig"
)

// validWGPublicKey reports whether s is a WireGuard public key (base64,
// 32 bytes decoded).
func validWGPublicKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

func peerOwnAddress(p vpn.Peer) string {
	for _, a := range p.AllowedIPs {
		if _, ipnet, err := net.ParseCIDR(a); err == nil {
			ones, bits := ipnet.Mask.Size()
			if ones == bits {
				return a
			}
		}
	}
	return ""
}

func (s *Server) findPeer(ctx context.Context, prov vpn.Provider, publicKey string) (vpn.Peer, error) {
	peers, err := prov.ListPeers(ctx)
	if err != nil {
		return vpn.Peer{}, err
	}
	for _, p := range peers {
		if p.PublicKey == publicKey {
			return p, nil
		}
	}
	return vpn.Peer{}, fmt.Errorf("peer not found")
}

// disablePeer is the core disable used by the API handler and the expiry
// worker. wg-family peers are soft-disabled (kept for re-enable); cert-based
// peers, which have no soft-disable, are removed.
func (s *Server) disablePeer(ctx context.Context, providerName, pubkey string) error {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return fmt.Errorf("unknown provider %q", providerName)
	}

	// Cert-based providers can't soft-disable; remove instead.
	if _, certBased := prov.(vpn.ClientConfigProvider); certBased {
		if err := prov.RemovePeer(ctx, pubkey); err != nil {
			return err
		}
		s.invalidateStatus(providerName)
		return nil
	}

	target, err := s.findPeer(ctx, prov, pubkey)
	if err != nil {
		return err
	}
	if err := s.store.SaveDisabledPeer(ctx, store.DisabledPeer{
		Provider: providerName, PublicKey: pubkey, Name: target.Name,
		AllowedIPs: strings.Join(target.AllowedIPs, ","), Keepalive: target.PersistentKeepalive,
	}); err != nil {
		return err
	}
	if err := prov.RemovePeer(ctx, pubkey); err != nil {
		_ = s.store.DeleteDisabledPeer(ctx, providerName, pubkey)
		return err
	}
	s.invalidateStatus(providerName)
	return nil
}

func (s *Server) buildClientConfigText(ctx context.Context, providerName, pubkey string) (text, filename string, err error) {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return "", "", fmt.Errorf("unknown provider %q", providerName)
	}
	status, err := prov.Status(ctx)
	if err != nil {
		return "", "", err
	}
	target, err := s.findPeer(ctx, prov, pubkey)
	if err != nil {
		return "", "", err
	}

	blob, err := s.store.GetPeerSecret(ctx, providerName, pubkey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", "", fmt.Errorf("private key for this peer isn't stored (it may have been added outside the panel) -- config can't be regenerated")
		}
		return "", "", err
	}
	priv, err := s.enc.Open(blob)
	if err != nil {
		return "", "", err
	}

	// Route the client to the entire mesh except itself: every tunnel
	// network (so it can reach peers on the other VPN transport too) plus
	// every site subnet. This is what makes a WireGuard client and an
	// AmneziaWG client mutually reachable without NAT.
	routes, err := s.routesForPeer(ctx, providerName, target)
	if err != nil {
		return "", "", err
	}

	text = clientconfig.Build(clientconfig.Params{
		ClientPrivateKey:    priv,
		ClientAddress:       peerOwnAddress(target),
		DNS:                 status.DNS,
		MTU:                 status.MTU,
		ServerPublicKey:     status.PublicKey,
		Endpoint:            status.Endpoint,
		AllowedIPs:          routes,
		PersistentKeepalive: target.PersistentKeepalive,
	})
	return text, sanitizeFilename(target.Name), nil
}

// errNoAltProfile distinguishes "bad ?format= for this provider" (400) from
// any other download failure (500) once the two shapes share one helper.
var errNoAltProfile = errors.New("provider offers no alternative profiles")

// buildPeerDownload produces one peer's downloadable config/profile,
// covering both provider shapes: certificate-based (OpenVPN/IKEv2, its own
// bundle or an alternative single-file profile via ?format=) and wg-family
// (built from stored keys via buildClientConfigText). Shared by the admin
// peer-download route and the self-service portal's ownership-checked twin.
func (s *Server) buildPeerDownload(ctx context.Context, providerName, pubkey, format string) (contentType, filename string, data []byte, err error) {
	if prov, ok := s.reg.Get(providerName); ok {
		if format != "" {
			cpp, ok := prov.(vpn.ClientProfileProvider)
			if !ok {
				return "", "", nil, errNoAltProfile
			}
			fn, d, err := cpp.ClientProfile(ctx, pubkey, format)
			if err != nil {
				return "", "", nil, err
			}
			return profileContentType(fn), fn, d, nil
		}
		if ccp, ok := prov.(vpn.ClientConfigProvider); ok {
			fn, d, err := ccp.ClientConfigFile(ctx, pubkey)
			if err != nil {
				return "", "", nil, err
			}
			return profileContentType(fn), fn, d, nil
		}
	}
	text, filename, err := s.buildClientConfigText(ctx, providerName, pubkey)
	if err != nil {
		return "", "", nil, err
	}
	return "text/plain; charset=utf-8", filename + ".conf", []byte(text), nil
}

// errNoManualSetup is returned when a provider's client format isn't plain
// text (IKEv2's .p12, Xray's non-peer-based setup) -- there's nothing a
// user could type by hand for those, unlike WireGuard/AmneziaWG/OpenVPN's
// INI-style configs.
var errNoManualSetup = errors.New("manual setup not available for this provider type")

// buildPeerConfigText returns a peer's config as plain text for on-screen
// "manual setup" display (backlog item: some client devices/apps can't
// import a file, but can have each field typed in by hand) -- reuses
// buildPeerDownload's default (non-alt-profile) format and rejects
// anything that isn't actually human-typeable text.
func (s *Server) buildPeerConfigText(ctx context.Context, providerName, pubkey string) (string, error) {
	contentType, _, data, err := s.buildPeerDownload(ctx, providerName, pubkey, "")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(contentType, "text/plain") {
		return "", errNoManualSetup
	}
	return string(data), nil
}

// buildPeerQRPNG renders a peer's wg-family config as a QR code. Cert-based
// bundles (multi-file, not a single scannable config) aren't QR'd here --
// matches the pre-existing behavior, unchanged by the download refactor above.
func (s *Server) buildPeerQRPNG(ctx context.Context, providerName, pubkey string) ([]byte, error) {
	text, _, err := s.buildClientConfigText(ctx, providerName, pubkey)
	if err != nil {
		return nil, err
	}
	return clientconfig.QRPNG(text)
}

func (s *Server) handlePeerConfig(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	pubkey, err := decodePeerID(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Downloading a config hands out private key material -- audit it.
	format := r.URL.Query().Get("format")
	target := providerName + "/" + pubkey
	if format != "" {
		target += " (" + format + ")"
	}
	s.audit(r.Context(), "peer.config.download", target)

	contentType, filename, data, err := s.buildPeerDownload(r.Context(), providerName, pubkey, format)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNoAltProfile) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write(data)
}

// GET /api/providers/{provider}/peers/{id}/config/text — the same config,
// as plain text for on-screen "manual setup" display (some client
// apps/devices can't import a file but a person can type each field in by
// hand). Same private-key-material sensitivity as the download, so audited
// the same way.
func (s *Server) apiPeerConfigText(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	pubkey, err := decodePeerID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "peer not found", "клиент не найден"))
		return
	}
	s.audit(r.Context(), "peer.config.manual_view", providerName+"/"+pubkey)
	text, err := s.buildPeerConfigText(r.Context(), providerName, pubkey)
	if err != nil {
		if errors.Is(err, errNoManualSetup) {
			writeErr(w, http.StatusBadRequest, msg(r, "manual setup isn't available for this provider type", "ручная настройка недоступна для этого типа провайдера"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]string{"text": text})
}

func (s *Server) handlePeerQR(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	pubkey, err := decodePeerID(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.audit(r.Context(), "peer.config.qr", providerName+"/"+pubkey)
	png, err := s.buildPeerQRPNG(r.Context(), providerName, pubkey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

// profileContentType picks a MIME type from a profile filename so browsers /
// devices handle the download correctly.
func profileContentType(filename string) string {
	switch {
	case strings.HasSuffix(filename, ".mobileconfig"):
		return "application/x-apple-aspen-config"
	case strings.HasSuffix(filename, ".p12"):
		return "application/x-pkcs12"
	case strings.HasSuffix(filename, ".sswan"):
		return "application/json; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}

func sanitizeFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "client"
	}
	return b.String()
}
