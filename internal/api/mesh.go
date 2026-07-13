package api

import (
	"context"
	"log/slog"
	"net"

	"protean/internal/vpn"
)

// Mesh-capable instances come from s.meshCapableInstances() (wg-family types).
// Whether each participates is a per-provider setting
// (ProviderSettings.MeshEnabled), off by default -- a standalone parallel tunnel.

// tunnelNetwork turns an interface address like "10.10.0.1/24" into its
// network CIDR "10.10.0.0/24". The interface Address may be a comma-separated
// dual-stack list ("10.10.0.1/24, fd00::1/64"); the first (IPv4) entry is used.
func tunnelNetwork(address string) (string, bool) {
	_, ipnet, err := net.ParseCIDR(vpn.FirstCIDR(address))
	if err != nil {
		return "", false
	}
	return ipnet.String(), true
}

func (s *Server) providerTunnelCIDR(ctx context.Context, name string) (string, bool) {
	prov, ok := s.reg.Get(name)
	if !ok {
		return "", false
	}
	status, err := s.providerStatus(ctx, prov)
	if err != nil || !status.Up || status.Address == "" {
		return "", false
	}
	return tunnelNetwork(status.Address)
}

// allTunnelCIDRs returns tunnel networks of every up capable interface,
// regardless of mesh membership -- used for overlap checks (two interfaces
// must never share a range even if run in parallel).
func (s *Server) allTunnelCIDRs(ctx context.Context, serverID string) []string {
	var cidrs []string
	for _, name := range s.meshCapableInstances(serverID) {
		if cidr, ok := s.providerTunnelCIDR(ctx, name); ok {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

// meshTunnelCIDRsExcept returns tunnel networks of mesh-ENABLED providers on the
// SAME server as `exclude` (per-server mesh), excluding `exclude` itself.
func (s *Server) meshTunnelCIDRsExcept(ctx context.Context, exclude string) []string {
	var cidrs []string
	for _, name := range s.meshCapableInstances(serverPart(exclude)) {
		if name == exclude {
			continue
		}
		ps, err := s.store.GetProviderSettings(ctx, name)
		if err != nil || !ps.MeshEnabled {
			continue
		}
		if cidr, ok := s.providerTunnelCIDR(ctx, name); ok {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

// applyCertMeshForwarding adds/removes the host FORWARD-accept rule for a
// cert-based provider's subnet so it participates in the mesh. wg-family
// providers manage forwarding through their own PostUp rules and are skipped.
// Best-effort: logged, not fatal (server may not be up yet).
func (s *Server) applyCertMeshForwarding(ctx context.Context, providerName string, meshEnabled bool) {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return
	}
	if _, cert := prov.(vpn.ClientConfigProvider); !cert {
		return
	}
	cidr, ok := s.providerTunnelCIDR(ctx, providerName)
	if !ok {
		return // server not provisioned/up yet; will be applied at setup
	}
	action := "del"
	if meshEnabled {
		action = "add"
	}
	inst, ok := s.installerForProvider(providerName)
	if !ok {
		slog.Error("cert mesh forwarding: no installer for server", "provider", providerName)
		return
	}
	if err := inst.Forward(ctx, action, cidr); err != nil {
		slog.Error("cert mesh forwarding", "provider", providerName, "action", action, "err", err)
	}
}

// ReapplyMeshForwarding re-adds the host FORWARD rules for mesh-enabled
// cert-based providers. Called at startup because those rules (unlike
// wg-quick PostUp) don't survive a reboot. Best-effort, runs in background.
func (s *Server) ReapplyMeshForwarding(ctx context.Context) {
	s.goWorker(func() {
		for _, p := range s.reg.List() {
			if ctx.Err() != nil {
				return
			}
			if _, cert := p.(vpn.ClientConfigProvider); !cert {
				continue
			}
			ps, err := s.store.GetProviderSettings(ctx, p.Name())
			if err != nil || !ps.MeshEnabled {
				continue
			}
			s.applyCertMeshForwarding(ctx, p.Name(), true)
		}
	})
}

// meshAddressSpace returns every CIDR already in use (all interface tunnels +
// all catalogued site subnets), for overlap rejection.
func (s *Server) meshAddressSpace(ctx context.Context) ([]string, error) {
	cidrs := s.allTunnelCIDRs(ctx, "") // all servers: subnets are shared mesh-wide
	subnets, err := s.store.ListAllSubnets(ctx)
	if err != nil {
		return nil, err
	}
	for _, sn := range subnets {
		cidrs = append(cidrs, sn.CIDR)
	}
	return cidrs, nil
}

// routesForPeer builds the AllowedIPs for a client of providerName:
//   - its own interface's tunnel (reach same-provider peers),
//   - all catalogued site subnets,
//   - if the provider is mesh-enabled: the tunnels of the OTHER mesh-enabled
//     providers (so cross-provider clients see each other),
//   - if the provider has internet egress: a default route (0.0.0.0/0),
//
// minus the CIDRs the peer itself owns.
func (s *Server) routesForPeer(ctx context.Context, providerName string, peer vpn.Peer) ([]string, error) {
	settings, err := s.store.GetProviderSettings(ctx, providerName)
	if err != nil {
		return nil, err
	}

	var tunnels []string
	if own, ok := s.providerTunnelCIDR(ctx, providerName); ok {
		tunnels = append(tunnels, own)
	}
	if settings.MeshEnabled {
		tunnels = append(tunnels, s.meshTunnelCIDRsExcept(ctx, providerName)...)
	}

	subnets, err := s.store.ListAllSubnets(ctx)
	if err != nil {
		return nil, err
	}
	subnetCIDRs := make([]string, 0, len(subnets))
	for _, sn := range subnets {
		subnetCIDRs = append(subnetCIDRs, sn.CIDR)
	}

	return computeRoutes(peer, tunnels, subnetCIDRs, settings.InternetEgress), nil
}

// computeRoutes is the pure routing policy. With egress it returns a default
// route (0.0.0.0/0) that supersedes the specific ones; both are emitted and
// WireGuard collapses them fine.
func computeRoutes(peer vpn.Peer, tunnelCIDRs, subnetCIDRs []string, egress bool) []string {
	own := map[string]bool{}
	for _, a := range peer.AllowedIPs {
		if _, ipnet, err := net.ParseCIDR(a); err == nil {
			own[ipnet.String()] = true
		}
	}

	seen := map[string]bool{}
	var routes []string
	add := func(cidr string) {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return
		}
		norm := ipnet.String()
		if own[norm] || seen[norm] {
			return
		}
		seen[norm] = true
		routes = append(routes, norm)
	}

	for _, c := range tunnelCIDRs {
		add(c)
	}
	for _, c := range subnetCIDRs {
		add(c)
	}
	if egress {
		add("0.0.0.0/0")
	}
	return routes
}
