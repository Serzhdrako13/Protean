package api

import (
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
	NATCapable bool `json:"nat_capable"`
}

func toAPISubnet(sn store.Subnet, ownerName string) apiSubnet {
	return apiSubnet{
		ID: sn.ID, CIDR: sn.CIDR, Label: sn.Label, Provider: sn.Provider,
		OwnerNodeID: sn.OwnerNodeID, OwnerNodeName: ownerName,
		NATMode: sn.NATMode, NATCapable: sn.Provider != "",
	}
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
	out := make([]apiSubnet, 0, len(subnets))
	for _, sn := range subnets {
		ownerName := ""
		if sn.OwnerNodeID != nil {
			ownerName = nodeNames[*sn.OwnerNodeID]
		}
		out = append(out, toAPISubnet(sn, ownerName))
	}
	writeOK(w, out)
}

type apiSubnetCreateReq struct {
	CIDR  string `json:"cidr"`
	Label string `json:"label"`
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
	sn, err := s.store.CreateSubnet(r.Context(), "", cidr, strings.TrimSpace(req.Label), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.create", cidr)
	writeOK(w, toAPISubnet(sn, ""))
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
	writeOK(w, toAPISubnet(updated, ""))
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
