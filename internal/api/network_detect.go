package api

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"

	"protean/internal/store"
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

// DetectionDecision is one admin-reviewed line item from a
// detectNetworkStructure preview, as submitted to applyNetworkDetection.
type DetectionDecision struct {
	PeerID   string `json:"peer_id"`
	Action   string `json:"action"` // "create_node" | "skip" | "undismiss"
	NodeName string `json:"node_name,omitempty"`
	NodeKind string `json:"node_kind,omitempty"` // "router" | "device" | "other"
	SubnetsToCreate []struct {
		CIDR  string `json:"cidr"`
		Label string `json:"label"`
	} `json:"subnets_to_create,omitempty"`
	// MeshWith: sibling provider names the admin approved enabling mesh
	// with (each becomes a symmetric SetProviderSettings on both sides).
	MeshWith []string `json:"mesh_with,omitempty"`
}

// DetectionSummary is returned to the admin after applying a batch of
// decisions -- so "nothing happened" and "6 things happened" are both
// visibly obvious, not just a bare 200 OK.
type DetectionSummary struct {
	NodesCreated     int `json:"nodes_created"`
	SubnetsCreated   int `json:"subnets_created"`
	MeshPairsEnabled int `json:"mesh_pairs_enabled"`
	Skipped          int `json:"skipped"`
	AlreadyHandled   int `json:"already_handled"`
	Undismissed      int `json:"undismissed"`
}

// applyNetworkDetection commits a reviewed batch of decisions. Never
// touches the on-host conf file or the live interface -- only the DB,
// through the same primitives the manual Node/Subnet/Mesh admin actions
// already use. Idempotent: re-checks GetNodePeerOwnerID (defends a second
// concurrent apply) and the current Subnets catalog before creating
// anything, so re-running an apply (or two browser tabs racing) never
// duplicates a Node or a Subnet.
func (s *Server) applyNetworkDetection(ctx context.Context, providerName string, decisions []DetectionDecision) (DetectionSummary, error) {
	var summary DetectionSummary

	existingSubnets, err := s.store.ListAllSubnets(ctx)
	if err != nil {
		return summary, err
	}
	existingByCIDR := map[string]bool{}
	for _, sn := range existingSubnets {
		existingByCIDR[sn.CIDR] = true
	}
	meshDone := map[string]bool{} // avoid re-toggling the same pair twice within one apply

	for _, d := range decisions {
		pubKey, err := decodePeerID(d.PeerID)
		if err != nil {
			continue
		}

		switch d.Action {
		case "skip":
			if err := s.store.SetPeerDetectionDismissed(ctx, providerName, d.PeerID); err != nil {
				return summary, err
			}
			summary.Skipped++

		case "undismiss":
			// Brings a previously-dismissed peer back into the next
			// preview -- e.g. it was dismissed by mistake, or the conf
			// gained a "# Name:" comment since.
			if err := s.store.ClearPeerDetectionDismissed(ctx, providerName, d.PeerID); err != nil {
				return summary, err
			}
			summary.Undismissed++

		case "create_node":
			// Node creation is gated on not-already-owned, but a peer that
			// already became a Node in an earlier apply (e.g. before a
			// sibling mesh-capable instance existed on this server) must
			// still be able to pick up newly-relevant subnets/mesh here --
			// otherwise every later addition would demand the admin
			// manually redo mesh/subnet setup outside this flow. Only the
			// node-creation step itself is skipped for an owned peer.
			ownerNodeID, owned, err := s.store.GetNodePeerOwnerID(ctx, providerName, d.PeerID)
			if err != nil {
				return summary, err
			}
			if owned {
				summary.AlreadyHandled++
			} else {
				name := strings.TrimSpace(d.NodeName)
				if name == "" {
					continue // Node.Name is NOT NULL -- nothing sane to create
				}
				kind := d.NodeKind
				if kind != "router" && kind != "device" && kind != "other" {
					kind = "router"
				}
				node, err := s.store.CreateNode(ctx, store.Node{
					Name: name, Kind: kind, Role: "network_node",
					Description: "Автоматически определено при импорте существующей конфигурации",
				})
				if err != nil {
					return summary, err
				}
				if err := s.store.SetNodePeer(ctx, providerName, d.PeerID, node.ID); err != nil {
					return summary, err
				}
				// pubKey, not d.PeerID: peer_category is keyed by the raw
				// public key (see api_peers.go's own SetPeerCategory
				// calls), unlike node_peer which is keyed by the encoded
				// urlID.
				if err := s.store.SetPeerCategory(ctx, providerName, pubKey, "site"); err != nil {
					return summary, err
				}
				s.audit(ctx, "node.create", name+" (auto-detected from "+providerName+")")
				summary.NodesCreated++
				ownerNodeID = node.ID
			}

			var groupID *int64
			if len(d.SubnetsToCreate) > 0 {
				gid, err := s.ensureProviderGroup(ctx, providerName)
				if err != nil {
					return summary, err
				}
				groupID = &gid
			}
			for _, sn := range d.SubnetsToCreate {
				cidr := strings.TrimSpace(sn.CIDR)
				if cidr == "" || existingByCIDR[cidr] {
					continue
				}
				if _, err := s.store.CreateSubnet(ctx, providerName, cidr, sn.Label, &ownerNodeID, groupID); err != nil {
					return summary, err
				}
				existingByCIDR[cidr] = true
				s.audit(ctx, "subnet.create", cidr)
				summary.SubnetsCreated++
			}

			for _, sib := range d.MeshWith {
				pairKey := meshPairKey(providerName, sib)
				if meshDone[pairKey] {
					continue
				}
				if err := s.enableMeshPair(ctx, providerName, sib); err != nil {
					return summary, err
				}
				meshDone[pairKey] = true
				summary.MeshPairsEnabled++
			}
		}
	}
	return summary, nil
}

func meshPairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// enableMeshPair turns MeshEnabled on for BOTH sides of a pair -- mesh is
// symmetric (meshTunnelCIDRsExcept is queried from both directions), so a
// one-sided toggle would be meaningless. A no-op for a side that's
// already enabled. Mirrors apiMeshSettingsUpdate's hot-apply (api_network.go)
// instead of only flipping the DB flag: for a cert-based instance the
// flag alone changes nothing on the host until it's re-provisioned
// (route push + FORWARD rules), and any instance needs ip_forward
// actually on when mesh is turning on, not just assumed from the
// interactive setup-host.sh bootstrap. Apply failures are logged, not
// returned -- a host-side hiccup on one side shouldn't abort the rest
// of the batch or roll back the DB flag that already correctly
// reflects the admin's decision.
func (s *Server) enableMeshPair(ctx context.Context, a, b string) error {
	if err := s.reconcileMeshGroups(ctx, a, b); err != nil {
		slog.Error("reconcile mesh groups failed", "a", a, "b", b, "err", err)
	}
	for _, name := range []string{a, b} {
		ps, err := s.store.GetProviderSettings(ctx, name)
		if err != nil {
			return err
		}
		if ps.MeshEnabled {
			continue
		}
		ps.MeshEnabled = true
		if err := s.store.SetProviderSettings(ctx, ps); err != nil {
			return err
		}
		s.audit(ctx, "network.update", name+" (mesh enabled, auto-detected)")

		if prov, ok := s.reg.Get(name); ok {
			if _, certBased := prov.(vpn.ClientConfigProvider); certBased {
				if err := s.provisionCert(ctx, name); err != nil {
					slog.Error("provision cert-based mesh sibling failed", "provider", name, "err", err)
				}
			}
		}
		if inst, ok := s.installerForProvider(name); ok {
			if err := inst.EnsureIPForward(ctx); err != nil {
				slog.Error("ensure ip_forward failed", "provider", name, "err", err)
			} else {
				s.audit(ctx, "server.ip_forward_enabled", name)
			}
		}
	}
	return nil
}
