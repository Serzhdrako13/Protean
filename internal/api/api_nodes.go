package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"protean/internal/store"
)

var nodeKinds = map[string]bool{"router": true, "device": true, "other": true}
var nodeRoles = map[string]bool{"member": true, "network_node": true}

type apiNode struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Role        string    `json:"role"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	PeersOnline int       `json:"peers_online"`
	PeersTotal  int       `json:"peers_total"`
}

// nodeAggregateStatus sums online/total across every peer this node owns,
// across every provider -- mirrors how apiHomeServer aggregates a server's
// peer counts, just scoped to one node's owned peers instead of one server.
func (s *Server) nodeAggregateStatus(ctx context.Context, nodeID int64) (online, total int) {
	owned, err := s.store.ListNodeOwnedPeerKeys(ctx, nodeID)
	if err != nil {
		return 0, 0
	}
	for _, o := range owned {
		prov, ok := s.reg.Get(o.Provider)
		if !ok {
			continue
		}
		pubkey, derr := decodePeerID(o.PeerKey)
		if derr != nil {
			continue
		}
		total++
		peers, err := s.providerPeers(ctx, prov)
		if err != nil {
			continue
		}
		for _, p := range peers {
			if p.PublicKey == pubkey && p.Online {
				online++
				break
			}
		}
	}
	return online, total
}

// GET /api/nodes
func (s *Server) apiNodesList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiNode, 0, len(nodes))
	for _, n := range nodes {
		online, total := s.nodeAggregateStatus(ctx, n.ID)
		out = append(out, apiNode{
			ID: n.ID, Name: n.Name, Kind: n.Kind, Role: n.Role, Description: n.Description,
			CreatedAt: n.CreatedAt, PeersOnline: online, PeersTotal: total,
		})
	}
	writeOK(w, out)
}

type apiNodeWriteReq struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Role        string `json:"role"`
	Description string `json:"description"`
}

func (s *Server) validNodeWriteReq(r *http.Request, req apiNodeWriteReq) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New(msg(r, "name required", "требуется имя"))
	}
	if !nodeKinds[req.Kind] {
		return errors.New(msg(r, "unknown kind", "неизвестный тип"))
	}
	if !nodeRoles[req.Role] {
		return errors.New(msg(r, "unknown role", "неизвестная роль"))
	}
	return nil
}

// POST /api/nodes
func (s *Server) apiNodesCreate(w http.ResponseWriter, r *http.Request) {
	var req apiNodeWriteReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.validNodeWriteReq(r, req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.store.CreateNode(r.Context(), store.Node{
		Name: strings.TrimSpace(req.Name), Kind: req.Kind, Role: req.Role,
		Description: strings.TrimSpace(req.Description),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "node.create", n.Name)
	writeOK(w, apiNode{ID: n.ID, Name: n.Name, Kind: n.Kind, Role: n.Role, Description: n.Description, CreatedAt: n.CreatedAt})
}

// PUT /api/nodes/{id}
func (s *Server) apiNodesUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiNodeWriteReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.validNodeWriteReq(r, req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateNode(r.Context(), id, strings.TrimSpace(req.Name), req.Kind, req.Role, strings.TrimSpace(req.Description)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "node.update", strconv.FormatInt(id, 10))
	writeOK(w, nil)
}

// removeNodePeers revokes (host-side) every peer a node owns and clears
// its node_peer rows -- mirrors removeUserPeers (api_users.go), same
// best-effort philosophy: an unreachable host shouldn't block deletion.
func (s *Server) removeNodePeers(ctx context.Context, nodeID int64) {
	owned, err := s.store.ListNodeOwnedPeerKeys(ctx, nodeID)
	if err != nil {
		slog.Warn("remove node peers: list owned", "node_id", nodeID, "err", err)
		return
	}
	for _, o := range owned {
		if prov, ok := s.reg.Get(o.Provider); ok {
			if pubkey, derr := decodePeerID(o.PeerKey); derr == nil {
				if err := prov.RemovePeer(ctx, pubkey); err != nil {
					slog.Warn("remove node peers: remove peer", "provider", o.Provider, "err", err)
				}
				s.invalidateStatus(o.Provider)
			}
		}
		if err := s.store.ClearNodePeer(ctx, o.Provider, o.PeerKey); err != nil {
			slog.Warn("remove node peers: clear owner", "provider", o.Provider, "err", err)
		}
	}
}

// DELETE /api/nodes/{id}
func (s *Server) apiNodesDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	n, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	s.removeNodePeers(r.Context(), id)
	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "node.delete", n.Name)
	writeOK(w, nil)
}

// apiNodeAccessRow is one provider instance as shown in the Nodes page's
// expandable per-node access panel -- richer than apiUserAccessRow: a node
// has no login/portal, so there's no pending/approved/denied dance, but the
// admin needs more operational detail per row (assigned address, live
// online/traffic, and -- the whole point of this feature -- that
// instance's current internet_egress/NAT state right there, not buried on
// a separate settings tab).
type apiNodeAccessRow struct {
	Provider       string `json:"provider"`
	ProviderLabel  string `json:"provider_label"`
	Type           string `json:"type"`
	Interface      string `json:"interface"`
	ServerID       string `json:"server_id"`
	Description    string `json:"description,omitempty"`
	State          string `json:"state"` // "granted" | "none"
	Address        string `json:"address,omitempty"`
	Online         bool   `json:"online"`
	LastHandshake  string `json:"last_handshake,omitempty"`
	RxBytes        uint64 `json:"rx_bytes"`
	TxBytes        uint64 `json:"tx_bytes"`
	InternetEgress bool   `json:"internet_egress"`
}

// GET /api/nodes/{id}/access
func (s *Server) apiNodeAccessList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	node, err := s.store.GetNode(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	owned, err := s.store.ListNodeOwnedPeerKeys(ctx, node.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ownedByProvider := map[string]store.OwnedNodePeerKey{}
	for _, o := range owned {
		ownedByProvider[o.Provider] = o
	}
	labels := s.instanceLabels(ctx)
	descriptions := s.instanceDescriptions(ctx)

	out := []apiNodeAccessRow{}
	for _, prov := range s.reg.List() {
		if prov.Type() == "xray" {
			continue
		}
		name := prov.Name()
		row := apiNodeAccessRow{
			Provider: name, ProviderLabel: s.providerLabel(name, labels),
			Type: prov.Type(), Interface: localName(name), ServerID: serverPart(name),
			Description: descriptions[name], State: "none",
		}
		if ps, err := s.store.GetProviderSettings(ctx, name); err == nil {
			row.InternetEgress = ps.InternetEgress
		}
		if o, ok := ownedByProvider[name]; ok {
			row.State = "granted"
			if pubkey, derr := decodePeerID(o.PeerKey); derr == nil {
				if peers, perr := s.providerPeers(ctx, prov); perr == nil {
					for _, p := range peers {
						if p.PublicKey != pubkey {
							continue
						}
						if len(p.AllowedIPs) > 0 {
							row.Address = p.AllowedIPs[0]
						}
						row.Online = p.Online
						if !p.LastHandshake.IsZero() {
							row.LastHandshake = p.LastHandshake.Format(time.RFC3339)
						}
						row.RxBytes = p.RxBytes
						row.TxBytes = p.TxBytes
						break
					}
				}
			}
		}
		out = append(out, row)
	}
	writeOK(w, out)
}

type apiNodeAccessSetReq struct {
	Enabled bool `json:"enabled"`
}

// revokeNodeProviderAccess mirrors revokeUserProviderAccess: removes the
// real peer host-side (best-effort) and clears node_peer ownership.
func (s *Server) revokeNodeProviderAccess(ctx context.Context, nodeID int64, provider string) {
	owned, err := s.store.ListNodeOwnedPeerKeys(ctx, nodeID)
	if err != nil {
		slog.Warn("revoke node provider access: list owned", "node_id", nodeID, "err", err)
		return
	}
	for _, o := range owned {
		if o.Provider != provider {
			continue
		}
		if prov, ok := s.reg.Get(o.Provider); ok {
			if pubkey, derr := decodePeerID(o.PeerKey); derr == nil {
				if err := prov.RemovePeer(ctx, pubkey); err != nil {
					slog.Warn("revoke node provider access: remove peer", "provider", o.Provider, "err", err)
				}
				s.invalidateStatus(o.Provider)
			}
		}
		if err := s.store.ClearNodePeer(ctx, o.Provider, o.PeerKey); err != nil {
			slog.Warn("revoke node provider access: clear owner", "provider", o.Provider, "err", err)
		}
	}
}

// POST /api/nodes/{id}/access/{provider} -- the Nodes page's per-provider
// access switch. No pending/approved/denied dance (unlike the portal-user
// equivalent): a node has no login to request anything, so an admin's
// toggle either grants immediately or it doesn't. network_node-role nodes
// are additionally guarded against sharing an instance with another
// network_node -- see HasNetworkNodePeer.
func (s *Server) apiNodeAccessSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	node, err := s.store.GetNode(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	provider := r.PathValue("provider")
	prov, ok := s.reg.Get(provider)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	if prov.Type() == "xray" {
		writeErr(w, http.StatusBadRequest, msg(r, "node access for Xray is not supported", "доступ узлов для Xray не поддерживается"))
		return
	}
	var req apiNodeAccessSetReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}

	if !req.Enabled {
		s.revokeNodeProviderAccess(ctx, node.ID, provider)
		s.audit(ctx, "node.access.revoke", node.Name+"/"+provider)
		writeOK(w, nil)
		return
	}

	if owned, err := s.store.ListNodeOwnedPeerKeys(ctx, node.ID); err == nil {
		for _, o := range owned {
			if o.Provider == provider {
				writeOK(w, nil) // already granted -- idempotent no-op
				return
			}
		}
	}

	if node.Role == "network_node" {
		conflict, err := s.store.HasNetworkNodePeer(ctx, provider, node.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if conflict {
			writeErr(w, http.StatusBadRequest, msg(r,
				"this instance already has another network node on it -- internet-egress/NAT is a per-instance setting, create a dedicated instance for this node instead",
				"на этом интерфейсе уже есть другой «узел сети» — NAT/интернет-доступ настраивается на весь интерфейс целиком, создайте для этого узла отдельный инстанс"))
			return
		}
	}

	if !autoProvisionableTypes[prov.Type()] {
		writeErr(w, http.StatusBadRequest, msg(r,
			"this provider type requires manually creating the client on the provider page, then assigning this node as its owner there",
			"для этого типа провайдера нужно вручную создать клиента на странице провайдера, а затем назначить владельцем этот узел"))
		return
	}

	urlID, result, err := s.autoProvisionPeer(ctx, provider, prov, node.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetNodePeer(ctx, provider, urlID, node.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, _, _, err := s.buildPeerDownload(ctx, provider, result.Peer.PublicKey, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r, "post-creation check failed: %v", "проверка после создания не пройдена: %v", err))
		return
	}
	s.invalidateStatus(provider)
	s.audit(ctx, "node.access.grant", node.Name+"/"+provider)
	writeOK(w, nil)
}

type apiPeerNodeOwnerReq struct {
	NodeID int64 `json:"node_id"`
	// NewNodeName/NewNodeKind: create-on-the-fly, mirroring
	// resolveGroupID's network-group pattern (api_subnets.go) -- lets the
	// peer's own Owner picker create a brand-new piece of equipment and
	// assign it in one request, instead of requiring a trip to the
	// separate Nodes/"Оборудование" page first. Real incident this
	// closes: that page's own standalone create form has no field to
	// link a peer at all, so a node created there could only ever be
	// linked via THIS endpoint anyway -- collapsing both steps into one
	// removes the easy-to-miss second step entirely. Role always defaults
	// to "member" here (the less common "network_node" role -- one
	// dedicated instance per node -- stays an explicit Оборудование edit,
	// not a quick-create decision). Only used when NodeID is 0.
	NewNodeName string `json:"new_node_name,omitempty"`
	NewNodeKind string `json:"new_node_kind,omitempty"`
}

// POST /api/providers/{provider}/peers/{id}/node-owner -- assigns a node as
// a peer's owner, for the manual-creation fallback (cert-based providers:
// an admin creates the client normally via "Add client", then assigns a
// node here instead of a portal user). Mirrors apiPeerSetOwner, kept as a
// separate endpoint/table rather than widening peer_owner -- see the plan
// doc. Mutual exclusion with peer_owner is enforced here and in
// apiPeerSetOwner: a peer can never have both kinds of owner at once.
func (s *Server) apiPeerSetNodeOwner(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	peerID := r.PathValue("id")
	if !s.instanceExists(provider) {
		writeErr(w, http.StatusNotFound, msg(r, "unknown provider", "неизвестный провайдер"))
		return
	}
	var req apiPeerNodeOwnerReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.NodeID == 0 && strings.TrimSpace(req.NewNodeName) == "" {
		if err := s.store.ClearNodePeer(r.Context(), provider, peerID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r.Context(), "peer.node_owner.clear", provider+"/"+peerID)
		writeOK(w, nil)
		return
	}
	var node store.Node
	if req.NodeID == 0 {
		kind := req.NewNodeKind
		if !nodeKinds[kind] {
			kind = "device"
		}
		created, err := s.store.CreateNode(r.Context(), store.Node{
			Name: strings.TrimSpace(req.NewNodeName), Kind: kind, Role: "member",
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r.Context(), "node.create", created.Name+" (from peer owner picker)")
		node = created
	} else {
		got, err := s.store.GetNode(r.Context(), req.NodeID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, msg(r, "unknown node", "неизвестный узел"))
			return
		}
		node = got
	}
	if _, has, err := s.store.GetPeerOwnerUserID(r.Context(), provider, peerID); err == nil && has {
		writeErr(w, http.StatusBadRequest, msg(r,
			"this client already has a portal-user owner -- clear it first",
			"у этого клиента уже есть владелец-пользователь портала, сначала снимите его"))
		return
	}
	if err := s.store.SetNodePeer(r.Context(), provider, peerID, node.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "peer.node_owner.set", provider+"/"+peerID+" -> "+node.Name)
	writeOK(w, nil)
}
