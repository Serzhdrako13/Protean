package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"protean/internal/store"
	"protean/internal/vpn"
)

type apiSubnet struct {
	ID            int64  `json:"id"`
	CIDR          string `json:"cidr"`
	Label         string `json:"label"`
	Provider      string `json:"provider,omitempty"`
	OwnerNodeID   *int64 `json:"owner_node_id,omitempty"`
	OwnerNodeName string `json:"owner_node_name,omitempty"`
	NATMode       string `json:"nat_mode"`
	// NATCapable is false when Provider is unknown (a manually-catalogued
	// subnet with no known adopted router) -- there's no host to apply the
	// masquerade rule on.
	NATCapable bool   `json:"nat_capable"`
	GroupID    *int64 `json:"group_id,omitempty"`
	GroupName  string `json:"group_name,omitempty"`
}

func toAPISubnet(sn store.Subnet, ownerName, groupName string) apiSubnet {
	return apiSubnet{
		ID: sn.ID, CIDR: sn.CIDR, Label: sn.Label, Provider: sn.Provider,
		OwnerNodeID: sn.OwnerNodeID, OwnerNodeName: ownerName,
		NATMode: sn.NATMode, NATCapable: sn.Provider != "",
		GroupID: sn.GroupID, GroupName: groupName,
	}
}

// groupName resolves a group id to its name, or "" if nil/unknown. Meant
// for single-subnet endpoints -- list endpoints should build a
// map[int64]string from one ListNetworkGroups call instead (see
// apiSubnetsList) to avoid an N+1 lookup.
func (s *Server) groupName(ctx context.Context, groupID *int64) string {
	if groupID == nil {
		return ""
	}
	g, err := s.store.GetNetworkGroup(ctx, *groupID)
	if err != nil {
		return ""
	}
	return g.Name
}

// GET /api/subnets
func (s *Server) apiSubnetsList(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.store.ListAllSubnets(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodeNames := map[int64]string{}
	if nodes, err := s.store.ListNodes(r.Context()); err == nil {
		for _, n := range nodes {
			nodeNames[n.ID] = n.Name
		}
	}
	groupNames := map[int64]string{}
	if groups, err := s.store.ListNetworkGroups(r.Context()); err == nil {
		for _, g := range groups {
			groupNames[g.ID] = g.Name
		}
	}
	out := make([]apiSubnet, 0, len(subnets))
	for _, sn := range subnets {
		ownerName, groupName := "", ""
		if sn.OwnerNodeID != nil {
			ownerName = nodeNames[*sn.OwnerNodeID]
		}
		if sn.GroupID != nil {
			groupName = groupNames[*sn.GroupID]
		}
		out = append(out, toAPISubnet(sn, ownerName, groupName))
	}
	writeOK(w, out)
}

type apiSubnetCreateReq struct {
	CIDR         string `json:"cidr"`
	Label        string `json:"label"`
	OwnerNodeID  *int64 `json:"owner_node_id,omitempty"`
	GroupID      *int64 `json:"group_id,omitempty"`
	NewGroupName string `json:"new_group_name,omitempty"`
}

// POST /api/subnets
func (s *Server) apiSubnetsCreate(w http.ResponseWriter, r *http.Request) {
	var req apiSubnetCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	cidr := strings.TrimSpace(req.CIDR)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "invalid CIDR", "неверный CIDR"))
		return
	}
	existing, err := s.meshAddressSpace(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := vpn.CheckNoOverlap(cidr, existing); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.OwnerNodeID != nil {
		if _, err := s.store.GetNode(r.Context(), *req.OwnerNodeID); errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusBadRequest, msg(r, "unknown equipment", "неизвестное оборудование"))
			return
		} else if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	groupID, err := s.resolveGroupID(r.Context(), req.GroupID, req.NewGroupName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sn, err := s.store.CreateSubnet(r.Context(), "", cidr, strings.TrimSpace(req.Label), req.OwnerNodeID, groupID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.create", cidr)
	writeOK(w, toAPISubnet(sn, "", s.groupName(r.Context(), sn.GroupID)))
}

// resolveGroupID turns a (groupID, newGroupName) request pair into a
// single group id to persist: a non-empty newGroupName always wins and
// creates a fresh group; otherwise groupID is validated (ErrNotFound-safe
// callers should check first) and passed through as-is (nil = no group).
func (s *Server) resolveGroupID(ctx context.Context, groupID *int64, newGroupName string) (*int64, error) {
	if name := strings.TrimSpace(newGroupName); name != "" {
		grp, err := s.store.CreateNetworkGroup(ctx, name)
		if err != nil {
			return nil, err
		}
		return &grp.ID, nil
	}
	return groupID, nil
}

type apiSubnetNATReq struct {
	NATMode string `json:"nat_mode"` // "passthrough" | "masquerade"
}

// PUT /api/subnets/{id} -- toggles a subnet's NAT mode. Applies the host
// iptables rule (via Installer.SubnetNAT) BEFORE persisting: unlike
// enableMeshPair's "persist then best-effort apply" (which optimizes for
// not aborting a multi-item detection batch), this is a single manual
// toggle from the Subnets page, so surfacing a real apply failure beats
// silently claiming success.
func (s *Server) apiSubnetsUpdateNAT(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiSubnetNATReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.NATMode != "passthrough" && req.NATMode != "masquerade" {
		writeErr(w, http.StatusBadRequest, msg(r, "invalid nat mode", "неверный режим NAT"))
		return
	}

	sn, err := s.store.GetSubnet(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.NATMode == "masquerade" && sn.Provider == "" {
		writeErr(w, http.StatusBadRequest, msg(r,
			"this subnet has no known route -- NAT mode is unavailable",
			"у этой подсети нет известного маршрута -- режим NAT недоступен"))
		return
	}

	if req.NATMode != sn.NATMode {
		action := "del"
		if req.NATMode == "masquerade" {
			action = "add"
		}
		if inst, ok := s.installerForProvider(sn.Provider); ok {
			if err := inst.SubnetNAT(r.Context(), action, sn.CIDR); err != nil {
				writeErr(w, http.StatusInternalServerError, msgf(r,
					"applying the host rule failed: %v", "не удалось применить правило на хосте: %v", err))
				return
			}
		}
	}

	updated, err := s.store.SetSubnetNATMode(r.Context(), id, req.NATMode)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.nat_mode", updated.CIDR+" -> "+req.NATMode)
	writeOK(w, toAPISubnet(updated, "", s.groupName(r.Context(), updated.GroupID)))
}

type apiSubnetGroupReq struct {
	GroupID      *int64 `json:"group_id,omitempty"`
	NewGroupName string `json:"new_group_name,omitempty"`
}

// PUT /api/subnets/{id}/group -- change (or clear, with both fields
// empty/omitted) a subnet's network group. Kept separate from the NAT
// endpoint above rather than folded in: NAT and group are independent
// axes and a shared request struct would make "leave NAT as-is" and
// "clear the group" ambiguous from an omitted field.
func (s *Server) apiSubnetsUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiSubnetGroupReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	groupID, err := s.resolveGroupID(r.Context(), req.GroupID, req.NewGroupName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, err := s.store.SetSubnetGroup(r.Context(), id, groupID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.group", updated.CIDR)
	writeOK(w, toAPISubnet(updated, "", s.groupName(r.Context(), updated.GroupID)))
}

type apiSubnetLabelReq struct {
	Label string `json:"label"`
}

// PUT /api/subnets/{id}/label -- edit a subnet's free-text human label.
// The only way to fix an auto-filled label an admin doesn't want to keep
// (this field is purely descriptive, nothing else reads it).
func (s *Server) apiSubnetsUpdateLabel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	var req apiSubnetLabelReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	updated, err := s.store.SetSubnetLabel(r.Context(), id, strings.TrimSpace(req.Label))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.label", updated.CIDR)
	writeOK(w, toAPISubnet(updated, "", s.groupName(r.Context(), updated.GroupID)))
}

// DELETE /api/subnets/{id}
func (s *Server) apiSubnetsDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	if sn, err := s.store.GetSubnet(r.Context(), id); err == nil && sn.NATMode == "masquerade" && sn.Provider != "" {
		if inst, ok := s.installerForProvider(sn.Provider); ok {
			if err := inst.SubnetNAT(r.Context(), "del", sn.CIDR); err != nil {
				slog.Error("subnet delete: teardown NAT rule", "cidr", sn.CIDR, "err", err)
			}
		}
	}
	if err := s.store.DeleteSubnet(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.delete", strconv.FormatInt(id, 10))
	writeOK(w, nil)
}
