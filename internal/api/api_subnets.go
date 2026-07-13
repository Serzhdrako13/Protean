package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"protean/internal/vpn"
)

type apiSubnet struct {
	ID    int64  `json:"id"`
	CIDR  string `json:"cidr"`
	Label string `json:"label"`
}

// GET /api/subnets
func (s *Server) apiSubnetsList(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.store.ListAllSubnets(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiSubnet, 0, len(subnets))
	for _, sn := range subnets {
		out = append(out, apiSubnet{ID: sn.ID, CIDR: sn.CIDR, Label: sn.Label})
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
	sn, err := s.store.CreateSubnet(r.Context(), cidr, strings.TrimSpace(req.Label))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.create", cidr)
	writeOK(w, apiSubnet{ID: sn.ID, CIDR: sn.CIDR, Label: sn.Label})
}

// DELETE /api/subnets/{id}
func (s *Server) apiSubnetsDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "not found", "не найдено"))
		return
	}
	if err := s.store.DeleteSubnet(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "subnet.delete", strconv.FormatInt(id, 10))
	writeOK(w, nil)
}
