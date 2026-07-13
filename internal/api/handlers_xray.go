package api

import (
	"net/http"

	"protean/internal/vpn/clientconfig"
	"protean/internal/vpn/xray"
)

func (s *Server) xrayProvider(providerName string) (*xray.Provider, bool) {
	prov, ok := s.reg.Get(providerName)
	if !ok {
		return nil, false
	}
	xp, ok := prov.(*xray.Provider)
	return xp, ok
}

// handleXraySubscription returns a base64 subscription body (all client links),
// importable by Happ / v2rayN / nekoray.
func (s *Server) handleXraySubscription(w http.ResponseWriter, r *http.Request) {
	xp, ok := s.xrayProvider(r.PathValue("provider"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	sub, err := xp.Subscription(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(sub))
}

// handleXrayQR renders a QR PNG for one client's share link.
func (s *Server) handleXrayQR(w http.ResponseWriter, r *http.Request) {
	xp, ok := s.xrayProvider(r.PathValue("provider"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	name := r.URL.Query().Get("client")
	links, err := xp.ClientLinks(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, l := range links {
		if l.Name == name {
			png, err := clientconfig.QRPNG(l.Link)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(png)
			return
		}
	}
	http.NotFound(w, r)
}
