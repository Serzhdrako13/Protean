package api

import (
	"context"
	"errors"
	"sort"

	"protean/internal/vpn"
)

var (
	errUnknownProvider = errors.New("unknown provider")
	errNotWGFamily     = errors.New("network detection is only available for WireGuard/AmneziaWG instances")
)

// DetectedItem is one peer's classification result from
// detectNetworkStructure, shaped for direct JSON display in the review UI.
type DetectedItem struct {
	PeerID           string   `json:"peer_id"`
	Name             string   `json:"name"`
	HasName          bool     `json:"has_name"`
	OwnAddress       string   `json:"own_address,omitempty"`
	RoutedSubnets    []string `json:"routed_subnets,omitempty"`
	FullTunnel       bool     `json:"full_tunnel"`
	Anomalies        []string `json:"anomalies,omitempty"`
	AlreadyNodeOwned bool     `json:"already_node_owned"`
	AlreadyDismissed bool     `json:"already_dismissed"`
	// ExistingSubnetCIDRs are RoutedSubnets entries already present in the
	// global Subnets catalog -- nothing to create for these.
	ExistingSubnetCIDRs []string `json:"existing_subnet_cidrs,omitempty"`
	// MeshCandidates are RoutedSubnets entries that exactly equal a
	// SIBLING same-server mesh-capable instance's own tunnel network, not
	// a foreign LAN -- kept structurally separate from plain subnets so
	// "subnet" and "mesh" are never conflated in the response (each
	// element names the sibling provider, not just the CIDR, so the UI
	// can ask "enable mesh with <provider>?" instead of just showing a CIDR).
	MeshCandidates []MeshCandidate `json:"mesh_candidates,omitempty"`
	// SuggestedAction is "create_node" | "none" | "already_handled" | "anomaly".
	SuggestedAction string `json:"suggested_action"`
}

// MeshCandidate names one sibling mesh-capable instance whose own tunnel
// network exactly matches one of this peer's routed subnets.
type MeshCandidate struct {
	Provider string `json:"provider"`
	CIDR     string `json:"cidr"`
}

// detectNetworkStructure is a READ-ONLY analysis pass: it never writes to
// the DB, the on-host conf file, or the live interface (matching
// wgfamily.Provider.EnsureServer's own "never touch an already-existing
// hand-authored file" convention). Restricted to wg-family providers --
// OpenVPN/IKEv2 store their own site-subnet/CCD state and would need a
// separately-shaped reconciliation, deferred as a stretch goal.
func (s *Server) detectNetworkStructure(ctx context.Context, providerName string) ([]DetectedItem, string, error) {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return nil, "", errUnknownProvider
	}
	if t := prov.Type(); t != "wireguard" && t != "amneziawg" {
		return nil, "", errNotWGFamily
	}

	tunnelCIDR, up := s.providerTunnelCIDR(ctx, providerName)
	if !up {
		return nil, "", nil // interface down / no address yet -- nothing to detect
	}

	peers, err := s.providerPeers(ctx, prov)
	if err != nil {
		return nil, tunnelCIDR, err
	}

	subnets, err := s.store.ListAllSubnets(ctx)
	if err != nil {
		return nil, tunnelCIDR, err
	}
	existingSubnetCIDRs := map[string]bool{}
	for _, sn := range subnets {
		existingSubnetCIDRs[sn.CIDR] = true
	}

	// Sibling instances on the SAME server (mesh is per-server today, see
	// meshCapableInstances) -- their tunnel CIDRs are looked up regardless
	// of current MeshEnabled state, since finding "this routed subnet
	// already equals a sibling's own network" is exactly what determines
	// whether mesh SHOULD be turned on, not just whether it already is.
	siblingCIDRs := map[string]string{} // cidr -> provider name
	for _, sib := range s.meshCapableInstances(serverPart(providerName)) {
		if sib == providerName {
			continue
		}
		if cidr, ok := s.providerTunnelCIDR(ctx, sib); ok {
			siblingCIDRs[cidr] = sib
		}
	}

	dismissed, err := s.store.DismissedPeerKeys(ctx, providerName)
	if err != nil {
		return nil, tunnelCIDR, err
	}

	out := make([]DetectedItem, 0, len(peers))
	for _, p := range peers {
		urlID, err := encodePeerID(p.PublicKey)
		if err != nil {
			continue
		}
		class := vpn.ClassifyPeerRoutes(tunnelCIDR, p.AllowedIPs)

		item := DetectedItem{
			PeerID:        urlID,
			Name:          p.Name,
			HasName:       p.Name != "",
			OwnAddress:    class.OwnAddress,
			RoutedSubnets: class.SiteSubnets,
			FullTunnel:    class.FullTunnel,
			Anomalies:     class.Anomalies,
		}

		if _, owned, err := s.store.GetNodePeerOwnerID(ctx, providerName, urlID); err == nil {
			item.AlreadyNodeOwned = owned
		}
		item.AlreadyDismissed = dismissed[urlID]

		for _, cidr := range class.SiteSubnets {
			if sib, ok := siblingCIDRs[cidr]; ok {
				item.MeshCandidates = append(item.MeshCandidates, MeshCandidate{Provider: sib, CIDR: cidr})
				continue // a sibling's own tunnel network is mesh, never also offered as a plain subnet
			}
			if existingSubnetCIDRs[cidr] {
				item.ExistingSubnetCIDRs = append(item.ExistingSubnetCIDRs, cidr)
			}
		}

		switch {
		case item.AlreadyNodeOwned || item.AlreadyDismissed:
			item.SuggestedAction = "already_handled"
		case len(class.SiteSubnets) > 0 && item.HasName:
			item.SuggestedAction = "create_node"
		case len(class.Anomalies) > 0:
			item.SuggestedAction = "anomaly"
		case len(class.SiteSubnets) > 0 && !item.HasName:
			// A real routed subnet on a peer the conf file can't name --
			// surfaced, not silently skipped, so the admin knows a real
			// site router isn't being missed for a fixable reason.
			item.Anomalies = append(item.Anomalies, "no name in conf -- add a \"# Name:\" comment above this peer's [Peer] block to make it detectable")
			item.SuggestedAction = "anomaly"
		default:
			item.SuggestedAction = "none"
		}

		out = append(out, item)
	}

	sort.Slice(out, func(i, j int) bool {
		rank := func(a string) int {
			switch a {
			case "create_node":
				return 0
			case "anomaly":
				return 1
			case "already_handled":
				return 2
			default:
				return 3
			}
		}
		ri, rj := rank(out[i].SuggestedAction), rank(out[j].SuggestedAction)
		if ri != rj {
			return ri < rj
		}
		return out[i].Name < out[j].Name
	})

	return out, tunnelCIDR, nil
}
