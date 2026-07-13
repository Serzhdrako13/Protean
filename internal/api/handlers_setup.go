package api

import (
	"context"
	"fmt"
	"strconv"

	"protean/internal/vpn"
)

// wgServerProvisioner is wg-family's EnsureServer shape -- distinct from
// vpn.ServerProvisioner (cert-based: pushRoutes/redirectGateway) since
// wg-family needs the interface's own address/port/dns/mtu instead, and is
// a strict "first bring-up only" op rather than a safely-repeatable one
// (see wgfamily.Provider.EnsureServer's doc comment for why). Implemented
// by *wgfamily.Provider, so both wireguard.New and amneziawg.New results
// satisfy it.
type wgServerProvisioner interface {
	EnsureServer(ctx context.Context, address string, listenPort int, dns, mtu string) error
}

// provisionWGFamily brings a brand-new WireGuard/AmneziaWG instance's
// interface up for the first time, using whatever address/listen_port/
// dns/mtu were captured in its server_instances.Config at creation time
// (see ServerProvidersPage's "add provider" form) -- a no-op if the
// instance already has a working config (see EnsureServer).
func (s *Server) provisionWGFamily(ctx context.Context, providerName string) error {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return fmt.Errorf("unknown provider %q", providerName)
	}
	prov2, ok := prov.(wgServerProvisioner)
	if !ok {
		return fmt.Errorf("provider needs no setup")
	}
	instances, err := s.store.ListServerInstances(ctx, serverPart(providerName))
	if err != nil {
		return err
	}
	name := localName(providerName)
	var cfg map[string]string
	for _, inst := range instances {
		if inst.LocalName == name {
			cfg = inst.Config
			break
		}
	}
	listenPort, _ := strconv.Atoi(cfg["listen_port"])
	if err := prov2.EnsureServer(ctx, cfg["address"], listenPort, cfg["dns"], cfg["mtu"]); err != nil {
		return err
	}
	s.invalidateStatus(providerName)
	return nil
}

// provisionCert (re)provisions a cert-based server from its current settings +
// the subnet catalog: EnsureServer with the right push-routes/egress, then the
// mesh FORWARD rule. Shared by the setup button and the Network page (hot-apply).
func (s *Server) provisionCert(ctx context.Context, providerName string) error {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return fmt.Errorf("unknown provider %q", providerName)
	}
	prov2, ok := prov.(vpn.ServerProvisioner)
	if !ok {
		return fmt.Errorf("provider needs no setup")
	}
	settings, err := s.store.GetProviderSettings(ctx, providerName)
	if err != nil {
		return err
	}

	// All clients get routes to the site subnets, plus other mesh tunnels
	// when this provider is mesh-enabled.
	var pushRoutes []string
	if subs, err := s.store.ListAllSubnets(ctx); err == nil {
		for _, sn := range subs {
			pushRoutes = append(pushRoutes, sn.CIDR)
		}
	}
	if settings.MeshEnabled {
		pushRoutes = append(pushRoutes, s.meshTunnelCIDRsExcept(ctx, providerName)...)
	}

	if err := prov2.EnsureServer(ctx, pushRoutes, settings.InternetEgress); err != nil {
		return err
	}
	s.invalidateStatus(providerName)
	// Server is up now, so its subnet is known: apply the mesh FORWARD rule.
	s.applyCertMeshForwarding(ctx, providerName, settings.MeshEnabled)
	return nil
}
