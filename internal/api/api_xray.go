package api

import (
	"net/http"
	"strings"

	"protean/internal/vpn/xray"
)

type apiXrayStrategy struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Selected bool   `json:"selected"`
}

type apiXrayParam struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Value       string `json:"value"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
}

type apiXrayClient struct {
	Name string `json:"name"`
	Link string `json:"link"`
}

type apiXrayRelayHop struct {
	Host     string `json:"host"`
	Strategy string `json:"strategy"`
}

type apiXrayView struct {
	Provider      string            `json:"provider"`
	ProviderLabel string            `json:"provider_label"`
	Up            bool              `json:"up"`
	Configured    bool              `json:"configured"`
	Current       string            `json:"current"`
	HasRelay      bool              `json:"has_relay"`
	RelayChain    []apiXrayRelayHop `json:"relay_chain,omitempty"`
	Strategies    []apiXrayStrategy `json:"strategies"`
	MultiClient   bool              `json:"multi_client"`
	ParamSpecs    []apiXrayParam    `json:"param_specs"`
	Clients       []apiXrayClient   `json:"clients"`
}

func (s *Server) buildAPIXrayView(r *http.Request, providerName, selected string) (apiXrayView, bool) {
	view := apiXrayView{Provider: providerName, ProviderLabel: s.adminProviderLabel(providerName, s.instanceLabels(r.Context()))}
	xp, ok := s.xrayProvider(providerName)
	if !ok {
		return view, false
	}
	if st, err := xp.Status(r.Context()); err == nil {
		view.Up = st.Up
	}

	curStrategy, curParams, relays, err := xp.Current(r.Context())
	if err == nil {
		view.Configured = true
		view.Current = curStrategy
		if len(relays) > 0 {
			view.HasRelay = true
			for _, hop := range relays {
				view.RelayChain = append(view.RelayChain, apiXrayRelayHop{Host: hop.Host, Strategy: hop.Strategy})
			}
		}
		if links, lerr := xp.ClientLinks(r.Context()); lerr == nil {
			for _, l := range links {
				view.Clients = append(view.Clients, apiXrayClient{Name: l.Name, Link: l.Link})
			}
		}
	}
	if selected == "" {
		selected = curStrategy
	}
	if selected == "" && len(xray.All()) > 0 {
		selected = xray.All()[0].Name()
	}

	for _, st := range xray.All() {
		view.Strategies = append(view.Strategies, apiXrayStrategy{
			Name: st.Name(), Label: st.Label(), Selected: st.Name() == selected,
		})
	}
	if strat, ok := xray.Get(selected); ok {
		view.MultiClient = strat.MultiClient()
		for _, spec := range strat.Params() {
			val := ""
			if selected == curStrategy {
				val = curParams.Value(spec.Key)
			}
			if val == "" {
				val = spec.Default
			}
			view.ParamSpecs = append(view.ParamSpecs, apiXrayParam{
				Key: spec.Key, Label: spec.Label, Placeholder: spec.Placeholder, Value: val,
				Required: spec.Required, Secret: spec.Secret,
			})
		}
	}
	return view, true
}

// GET /api/providers/{provider}/xray?strategy=<name>
func (s *Server) apiXrayGet(w http.ResponseWriter, r *http.Request) {
	view, ok := s.buildAPIXrayView(r, r.PathValue("provider"), r.URL.Query().Get("strategy"))
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "not an Xray provider", "это не Xray-провайдер"))
		return
	}
	writeOK(w, view)
}

type apiXrayApplyReq struct {
	Strategy   string            `json:"strategy"`
	Params     map[string]string `json:"params"`
	RelayLinks []string          `json:"relay_links"`
}

// POST /api/providers/{provider}/xray
func (s *Server) apiXrayApply(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	xp, ok := s.xrayProvider(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "not an Xray provider", "это не Xray-провайдер"))
		return
	}
	var req apiXrayApplyReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "неверное тело запроса"))
		return
	}
	strat, ok := xray.Get(req.Strategy)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "unknown strategy", "неизвестная стратегия"))
		return
	}
	params := xray.Params{}
	for _, spec := range strat.Params() {
		if v := req.Params[spec.Key]; v != "" {
			params[spec.Key] = v
		}
	}
	var relays []xray.RelaySpec
	for i, link := range req.RelayLinks {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		rs, err := xray.ParseClientLink(link)
		if err != nil {
			writeErr(w, http.StatusBadRequest, msgf(r, "relay hop %d: %s", "переход реле %d: %s", i+1, err.Error()))
			return
		}
		relays = append(relays, rs)
	}
	if err := xp.Apply(r.Context(), req.Strategy, params, relays); err != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r, "apply failed: %s", "не удалось применить: %s", err.Error()))
		return
	}
	s.audit(r.Context(), "xray.apply", providerName+"/"+req.Strategy)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}

type apiXrayClientReq struct {
	Name string `json:"name"`
}

// POST /api/providers/{provider}/xray/clients
func (s *Server) apiXrayAddClient(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	xp, ok := s.xrayProvider(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "not an Xray provider", "это не Xray-провайдер"))
		return
	}
	var req apiXrayClientReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "неверное тело запроса"))
		return
	}
	if err := xp.AddClient(r.Context(), req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r, "add client: %s", "не удалось добавить клиента: %s", err.Error()))
		return
	}
	s.audit(r.Context(), "xray.client.add", providerName+"/"+req.Name)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}

// POST /api/providers/{provider}/xray/clients/remove
func (s *Server) apiXrayRemoveClient(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	xp, ok := s.xrayProvider(providerName)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "not an Xray provider", "это не Xray-провайдер"))
		return
	}
	var req apiXrayClientReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "неверное тело запроса"))
		return
	}
	if err := xp.RemoveClient(r.Context(), req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "xray.client.remove", providerName+"/"+req.Name)
	s.invalidateStatus(providerName)
	writeOK(w, nil)
}
