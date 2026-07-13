package api

import (
	"fmt"
	"net/http"
	"sort"

	"protean/internal/vpn"
)

type apiMeshIface struct {
	Provider          string `json:"provider"`
	Label             string `json:"label"`
	Up                bool   `json:"up"`
	ListenPort        int    `json:"listen_port"`
	PeerCount         int    `json:"peer_count"`
	TunnelCIDR        string `json:"tunnel_cidr,omitempty"`
	SupportsForward   bool   `json:"supports_forward"`
	ForwardingEnabled bool   `json:"forwarding_enabled"`
}

type apiMeshPeer struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Online   bool   `json:"online"`
}

type apiMeshSubnet struct {
	CIDR  string `json:"cidr"`
	Label string `json:"label"`
}

type apiMesh struct {
	ServerID   string          `json:"server_id"`
	Servers    []string        `json:"servers"`
	Interfaces []apiMeshIface  `json:"interfaces"`
	Peers      []apiMeshPeer   `json:"peers"`
	Subnets    []apiMeshSubnet `json:"subnets"`
	Warnings   []string        `json:"warnings"`
}

// GET /api/mesh?server=<id> — JSON twin of handleMeshPage (handlers_mesh.go).
func (s *Server) apiMeshGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := s.resolveServer(r)
	out := apiMesh{ServerID: serverID, Servers: s.serverIDs()}

	type labelledCIDR struct{ cidr, label string }
	var all []labelledCIDR
	labels := s.instanceLabels(ctx)

	for _, name := range s.meshCapableInstances(serverID) {
		prov, ok := s.reg.Get(name)
		if !ok {
			continue
		}
		iv := apiMeshIface{Provider: name, Label: s.adminProviderLabel(name, labels)}
		status, err := s.providerStatus(ctx, prov)
		if err == nil && status.Up {
			iv.Up = true
			iv.ListenPort = status.ListenPort
			iv.PeerCount = status.PeerCount
			if cidr, ok := tunnelNetwork(status.Address); ok {
				iv.TunnelCIDR = cidr
				all = append(all, labelledCIDR{cidr, iv.Label + " tunnel"})
			}
			if fm, ok := prov.(vpn.ForwardingManager); ok {
				iv.SupportsForward = true
				if enabled, err := fm.ForwardingEnabled(ctx); err == nil {
					iv.ForwardingEnabled = enabled
				}
			}
			if peers, err := s.providerPeers(ctx, prov); err == nil {
				for _, p := range peers {
					out.Peers = append(out.Peers, apiMeshPeer{
						Provider: name, Name: p.Name, Address: peerOwnAddress(p), Online: p.Online,
					})
				}
			}
		}
		out.Interfaces = append(out.Interfaces, iv)
	}

	subnets, err := s.store.ListAllSubnets(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, sn := range subnets {
		out.Subnets = append(out.Subnets, apiMeshSubnet{CIDR: sn.CIDR, Label: sn.Label})
		all = append(all, labelledCIDR{sn.CIDR, "subnet " + sn.CIDR})
	}

	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if err := vpn.CheckNoOverlap(all[i].cidr, []string{all[j].cidr}); err != nil {
				out.Warnings = append(out.Warnings, fmt.Sprintf("%s overlaps %s", all[i].label, all[j].label))
			}
		}
	}
	sort.Slice(out.Peers, func(i, j int) bool {
		if out.Peers[i].Provider != out.Peers[j].Provider {
			return out.Peers[i].Provider < out.Peers[j].Provider
		}
		return out.Peers[i].Name < out.Peers[j].Name
	})
	writeOK(w, out)
}

// POST /api/mesh/providers/{provider}/forwarding
func (s *Server) apiMeshEnableForwarding(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	prov, ok := s.reg.Get(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	fm, ok := prov.(vpn.ForwardingManager)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "provider does not support forwarding management", "провайдер не поддерживает управление форвардингом"))
		return
	}
	if err := fm.EnableForwarding(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "mesh.enable_forwarding", providerName)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}
