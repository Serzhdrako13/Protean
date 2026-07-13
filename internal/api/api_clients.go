package api

import (
	"net/http"
	"time"

	"protean/internal/store"
)

// apiClientRow is one real peer anywhere in the system, with its owner
// resolved across BOTH ownership tables (a portal user via peer_owner, or
// an equipment node via node_peer). Backs the "Клиенты сети → Все
// клиенты" unified overview -- deliberately duplicates data already
// reachable per-user (Users page) and per-node (Клиенты сети →
// Оборудование), an explicit ask given how many entities/relationships are
// now involved (server -> provider instance -> peer -> user OR node).
type apiClientRow struct {
	Provider      string `json:"provider"`
	ProviderLabel string `json:"provider_label"`
	ServerID      string `json:"server_id"`
	Type          string `json:"type"`
	PeerID        string `json:"peer_id"`
	Name          string `json:"name"`
	Category      string `json:"category,omitempty"`
	Online        bool   `json:"online"`
	LastHandshake string `json:"last_handshake,omitempty"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	// OwnerKind: "user" | "node" | "none".
	OwnerKind string `json:"owner_kind"`
	OwnerName string `json:"owner_name,omitempty"`
}

// GET /api/clients -- every real peer across every provider (Xray
// excluded, same as the node/user access-grant endpoints: its "clients"
// aren't peer-key-addressable the same way), owner resolved across both
// peer_owner and node_peer in one pass.
func (s *Server) apiClientsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userOwned, err := s.store.ListAllOwnedPeers(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	userOwnerByKey := map[string]store.GlobalPeerOwnerRow{}
	for _, o := range userOwned {
		userOwnerByKey[o.Provider+"|"+o.PeerKey] = o
	}

	nodeOwned, err := s.store.ListAllNodeOwnedPeers(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodeOwnerByKey := map[string]store.GlobalNodePeerRow{}
	for _, o := range nodeOwned {
		nodeOwnerByKey[o.Provider+"|"+o.PeerKey] = o
	}

	labels := s.instanceLabels(ctx)
	out := []apiClientRow{}
	for _, prov := range s.reg.List() {
		if prov.Type() == "xray" {
			continue
		}
		name := prov.Name()
		peers, err := s.providerPeers(ctx, prov)
		if err != nil {
			continue
		}
		cats, _ := s.store.PeerCategories(ctx, name)
		for _, p := range peers {
			urlID, err := encodePeerID(p.PublicKey)
			if err != nil {
				continue
			}
			key := name + "|" + urlID
			row := apiClientRow{
				Provider: name, ProviderLabel: s.providerLabel(name, labels),
				ServerID: serverPart(name), Type: prov.Type(),
				PeerID: urlID, Name: p.Name, Category: cats[p.PublicKey],
				Online: p.Online, RxBytes: p.RxBytes, TxBytes: p.TxBytes,
				OwnerKind: "none",
			}
			if !p.LastHandshake.IsZero() {
				row.LastHandshake = p.LastHandshake.Format(time.RFC3339)
			}
			if o, ok := userOwnerByKey[key]; ok {
				row.OwnerKind = "user"
				row.OwnerName = o.Username
			} else if o, ok := nodeOwnerByKey[key]; ok {
				row.OwnerKind = "node"
				row.OwnerName = o.NodeName
			}
			out = append(out, row)
		}
	}
	writeOK(w, out)
}
