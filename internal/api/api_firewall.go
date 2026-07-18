package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"protean/internal/firewall"
	"protean/internal/sshexec"
	"protean/internal/store"
	"protean/internal/vpn"
	"protean/internal/vpn/xray"
)

// --- shell-verb JSON payloads (installer.sh's firewall-* verbs) ---

type fwBaselineJSON struct {
	HasIptables        bool   `json:"has_iptables"`
	ConflictingManager bool   `json:"conflicting_manager"`
	Error              string `json:"error"`
}

type fwStatusJSON struct {
	Pending             bool   `json:"pending"`
	RemainingSecs       int    `json:"remaining_secs"`
	ConfirmedStateSaved bool   `json:"confirmed_state_saved"`
	CurrentRuleset      string `json:"current_ruleset"`
	Error               string `json:"error"`
}

type fwValidateJSON struct {
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type fwApplyJSON struct {
	Applied            bool   `json:"applied"`
	RollbackWindowSecs int    `json:"rollback_window_secs"`
	Error              string `json:"error"`
}

type fwConfirmJSON struct {
	Confirmed bool   `json:"confirmed"`
	Error     string `json:"error"`
}

type fwRollbackJSON struct {
	RolledBack bool   `json:"rolled_back"`
	Error      string `json:"error"`
}

// runFirewallVerb invokes one installer.sh firewall-* verb, embedding
// stdin as a quoted heredoc on the same command line -- the exact
// technique sshexec.Client.WriteFile already uses elsewhere, so untrusted
// ruleset text is never argv or shell-interpreted, just literal heredoc
// body.
func runFirewallVerb(ctx context.Context, client *sshexec.Client, verb string, args []string, stdin string) (string, error) {
	cmd := "sudo " + vpn.InstallerPath + " " + verb
	for _, a := range args {
		cmd += " " + a
	}
	if stdin != "" {
		cmd += " <<'PROTEAN_FW_EOF'\n" + stdin + "\nPROTEAN_FW_EOF"
	}
	return client.Run(ctx, cmd)
}

func providerTypeLabel(t string) string {
	switch t {
	case "wireguard":
		return "WireGuard"
	case "amneziawg":
		return "AmneziaWG"
	case "openvpn":
		return "OpenVPN"
	case "ikev2":
		return "IKEv2"
	case "xray":
		return "Xray"
	default:
		return t
	}
}

// instancePorts gathers each of serverID's live VPN instance ports for the
// firewall baseline, via the same registered providers the rest of the
// admin UI already queries. Skipped (not an error) if a provider isn't
// registered or isn't currently up -- nothing is listening on its port
// right now, so there's nothing to protect yet; re-checking after
// starting a new instance is the admin's own next step, matching the
// "baseline computed fresh at every apply" design.
func (s *Server) instancePorts(ctx context.Context, serverID string) []firewall.InstancePort {
	instances, err := s.store.ListServerInstances(ctx, serverID)
	if err != nil {
		return nil
	}
	var out []firewall.InstancePort
	for _, inst := range instances {
		prov, ok := s.reg.Get(serverID + ":" + inst.LocalName)
		if !ok {
			continue
		}
		label := fmt.Sprintf("%s (%s)", providerTypeLabel(inst.Type), inst.LocalName)
		switch inst.Type {
		case "wireguard", "amneziawg":
			if st, err := prov.Status(ctx); err == nil && st.Up && st.ListenPort > 0 {
				out = append(out, firewall.InstancePort{Label: label, Proto: "udp", Port: st.ListenPort})
			}
		case "openvpn":
			st, err := prov.Status(ctx)
			if err != nil || !st.Up || st.ListenPort <= 0 {
				continue
			}
			proto := "udp"
			if inst.Config["proto"] == "tcp" {
				proto = "tcp"
			}
			out = append(out, firewall.InstancePort{Label: label, Proto: proto, Port: st.ListenPort})
		case "ikev2":
			// No per-instance port exists in this codebase -- strongSwan's
			// two conventional IKE ports, always both when the shared
			// daemon is up.
			if st, err := prov.Status(ctx); err == nil && st.Up {
				out = append(out, firewall.InstancePort{Label: label, Proto: "udp", Port: 500})
				out = append(out, firewall.InstancePort{Label: label + " (NAT-T)", Proto: "udp", Port: 4500})
			}
		case "xray":
			st, err := prov.Status(ctx)
			if err != nil || !st.Up {
				continue
			}
			xp, ok := prov.(*xray.Provider)
			if !ok {
				continue
			}
			// "port" matches xray.Params' own (unexported) pPort key --
			// Params is a plain map[string]string, no exported accessor
			// for a single field exists, so this string is the stable
			// public contract with that package.
			if _, params, _, err := xp.Current(ctx); err == nil {
				if port, err := strconv.Atoi(params["port"]); err == nil && port > 0 {
					out = append(out, firewall.InstancePort{Label: label, Proto: "tcp", Port: port})
				}
			}
		}
	}
	return out
}

func (s *Server) computeBaseline(ctx context.Context, srv store.Server) []firewall.BaselinePort {
	return firewall.ComputeBaseline(srv.Port, s.instancePorts(ctx, srv.ID), srv.PanelHost, s.panelPorts)
}

func toFirewallRules(rules []store.FirewallRule) []firewall.Rule {
	var out []firewall.Rule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		out = append(out, firewall.Rule{Action: r.Action, Proto: r.Proto, PortSpec: r.PortSpec, SourceCIDR: r.SourceCIDR, Comment: r.Comment})
	}
	return out
}

// criticalPortsCSV formats baseline ports (minus SSH, passed separately to
// firewall-apply as its own arg) as "proto:port,proto:port,..." for the
// installer's host-side guard-insert.
func criticalPortsCSV(baseline []firewall.BaselinePort, sshPort int) string {
	s := ""
	for _, bp := range baseline {
		if bp.Proto == "tcp" && bp.Port == sshPort {
			continue // already covered by the dedicated ssh_port arg
		}
		if s != "" {
			s += ","
		}
		s += bp.Proto + ":" + strconv.Itoa(bp.Port)
	}
	return s
}

// renderFor loads a server's saved policy/rules and renders the effective
// ruleset -- the shared preparation step behind dry-run and apply.
func (s *Server) renderFor(ctx context.Context, serverID string) (srv store.Server, policy store.FirewallPolicy, rendered string, err error) {
	srv, err = s.store.GetServer(ctx, serverID)
	if err != nil {
		return
	}
	policy, err = s.store.GetFirewallPolicy(ctx, serverID)
	if err != nil {
		return
	}
	rules, err := s.store.ListFirewallRules(ctx, serverID)
	if err != nil {
		return
	}
	baseline := s.computeBaseline(ctx, srv)
	rendered = firewall.Render(firewall.Policy{DefaultIncoming: policy.DefaultIncoming}, baseline, toFirewallRules(rules))
	return srv, policy, rendered, nil
}

// --- API response/request shapes ---

type apiFirewallRule struct {
	ID         int64  `json:"id"`
	Ordering   int    `json:"ordering"`
	Action     string `json:"action"`
	Proto      string `json:"proto"`
	PortSpec   string `json:"port_spec"`
	SourceCIDR string `json:"source_cidr"`
	Comment    string `json:"comment"`
	Enabled    bool   `json:"enabled"`
}

type apiFirewallBaselinePort struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Label string `json:"label"`
}

type apiFirewallPolicy struct {
	Enabled            bool       `json:"enabled"`
	DefaultIncoming    string     `json:"default_incoming"`
	RollbackWindowSecs int        `json:"rollback_window_secs"`
	LastAppliedAt      *time.Time `json:"last_applied_at,omitempty"`
	LastConfirmedAt    *time.Time `json:"last_confirmed_at,omitempty"`
}

type apiFirewallStatus struct {
	Pending             bool `json:"pending"`
	RemainingSecs       int  `json:"remaining_secs"`
	ConfirmedStateSaved bool `json:"confirmed_state_saved"`
}

type apiFirewallGetResp struct {
	Policy   apiFirewallPolicy         `json:"policy"`
	Rules    []apiFirewallRule         `json:"rules"`
	Baseline []apiFirewallBaselinePort `json:"baseline"`
	Warnings []string                  `json:"warnings"`
	Status   *apiFirewallStatus        `json:"status,omitempty"`
}

// GET /api/servers/{id}/firewall
func (s *Server) apiFirewallGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	srv, err := s.store.GetServer(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	policy, err := s.store.GetFirewallPolicy(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rules, err := s.store.ListFirewallRules(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	baseline := s.computeBaseline(r.Context(), srv)
	baselineResp := make([]apiFirewallBaselinePort, 0, len(baseline))
	for _, bp := range baseline {
		baselineResp = append(baselineResp, apiFirewallBaselinePort{Proto: bp.Proto, Port: bp.Port, Label: bp.Label})
	}

	var status *apiFirewallStatus
	var warnings []string
	if s.mgr != nil {
		if client, closeFn, err := s.mgr.ConsoleClient(r.Context(), id); err == nil {
			func() {
				defer closeFn()
				if out, err := runFirewallVerb(r.Context(), client, "firewall-status", nil, ""); err == nil {
					var st fwStatusJSON
					if json.Unmarshal([]byte(out), &st) == nil {
						status = &apiFirewallStatus{Pending: st.Pending, RemainingSecs: st.RemainingSecs, ConfirmedStateSaved: st.ConfirmedStateSaved}
					}
				}
				if out, err := runFirewallVerb(r.Context(), client, "firewall-baseline", nil, ""); err == nil {
					var bl fwBaselineJSON
					if json.Unmarshal([]byte(out), &bl) == nil {
						if bl.ConflictingManager {
							warnings = append(warnings, msg(r,
								"a conflicting firewall manager (ufw/firewalld) is active on this host -- applying will refuse",
								"на этом хосте активен конфликтующий менеджер файрвола (ufw/firewalld) — применение будет отклонено"))
						}
						if !bl.HasIptables {
							warnings = append(warnings, msg(r,
								"iptables not found on this host -- applying will refuse",
								"iptables на этом хосте не найден — применение будет отклонено"))
						}
					}
				}
			}()
		}
	}

	rulesResp := make([]apiFirewallRule, 0, len(rules))
	for _, ru := range rules {
		rulesResp = append(rulesResp, apiFirewallRule{
			ID: ru.ID, Ordering: ru.Ordering, Action: ru.Action, Proto: ru.Proto,
			PortSpec: ru.PortSpec, SourceCIDR: ru.SourceCIDR, Comment: ru.Comment, Enabled: ru.Enabled,
		})
	}
	writeOK(w, apiFirewallGetResp{
		Policy: apiFirewallPolicy{
			Enabled: policy.Enabled, DefaultIncoming: policy.DefaultIncoming, RollbackWindowSecs: policy.RollbackWindowSecs,
			LastAppliedAt: policy.LastAppliedAt, LastConfirmedAt: policy.LastConfirmedAt,
		},
		Rules: rulesResp, Baseline: baselineResp, Warnings: warnings, Status: status,
	})
}

type apiFirewallPolicyReq struct {
	Enabled            bool   `json:"enabled"`
	DefaultIncoming    string `json:"default_incoming"`
	RollbackWindowSecs int    `json:"rollback_window_secs"`
}

// PUT /api/servers/{id}/firewall/policy
func (s *Server) apiFirewallPolicyPut(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req apiFirewallPolicyReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.DefaultIncoming != "drop" && req.DefaultIncoming != "accept" {
		writeErr(w, http.StatusBadRequest, msg(r, "default_incoming must be drop or accept", "default_incoming должен быть drop или accept"))
		return
	}
	if req.RollbackWindowSecs < 30 || req.RollbackWindowSecs > 3600 {
		writeErr(w, http.StatusBadRequest, msg(r, "rollback window must be between 30 and 3600 seconds", "окно отката должно быть от 30 до 3600 секунд"))
		return
	}
	if err := s.store.UpsertFirewallPolicy(r.Context(), store.FirewallPolicy{
		ServerID: id, Enabled: req.Enabled, DefaultIncoming: req.DefaultIncoming, RollbackWindowSecs: req.RollbackWindowSecs,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "firewall.policy.update", id)
	writeOK(w, nil)
}

type apiFirewallRuleReq struct {
	Action     string `json:"action"`
	Proto      string `json:"proto"`
	PortSpec   string `json:"port_spec"`
	SourceCIDR string `json:"source_cidr"`
	Comment    string `json:"comment"`
	Enabled    bool   `json:"enabled"`
}

// PUT /api/servers/{id}/firewall/rules -- replaces the whole custom rule
// set; a draft edit, applies nothing by itself.
func (s *Server) apiFirewallRulesPut(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req []apiFirewallRuleReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	rules := make([]store.FirewallRule, 0, len(req))
	for i, rr := range req {
		if rr.Action != "accept" && rr.Action != "drop" && rr.Action != "reject" {
			writeErr(w, http.StatusBadRequest, msg(r, "invalid rule action", "неверное действие правила"))
			return
		}
		if rr.Proto != "tcp" && rr.Proto != "udp" && rr.Proto != "any" {
			writeErr(w, http.StatusBadRequest, msg(r, "invalid rule protocol", "неверный протокол правила"))
			return
		}
		rules = append(rules, store.FirewallRule{
			ServerID: id, Ordering: i, Action: rr.Action, Proto: rr.Proto,
			PortSpec: rr.PortSpec, SourceCIDR: rr.SourceCIDR, Comment: rr.Comment, Enabled: rr.Enabled,
		})
	}
	if err := s.store.ReplaceFirewallRules(r.Context(), id, rules); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "firewall.rules.update", id)
	writeOK(w, nil)
}

type apiFirewallDryRunResp struct {
	Valid   bool     `json:"valid"`
	Error   string   `json:"error,omitempty"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// POST /api/servers/{id}/firewall/dry-run -- renders the effective
// ruleset, validates it on the host (iptables-restore --test, no changes
// made), and diffs it against the host's current live ruleset. Nothing
// on the host changes.
func (s *Server) apiFirewallDryRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "server manager not configured", "менеджер серверов не настроен"))
		return
	}
	_, _, rendered, err := s.renderFor(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	client, closeFn, err := s.mgr.ConsoleClient(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	defer closeFn()

	var current string
	if out, err := runFirewallVerb(r.Context(), client, "firewall-status", nil, ""); err == nil {
		var st fwStatusJSON
		if json.Unmarshal([]byte(out), &st) == nil {
			current = st.CurrentRuleset
		}
	}

	out, err := runFirewallVerb(r.Context(), client, "firewall-validate", nil, rendered)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var v fwValidateJSON
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		writeErr(w, http.StatusBadGateway, "unparseable validate response: "+out)
		return
	}
	added, removed := firewall.Diff(current, rendered)
	writeOK(w, apiFirewallDryRunResp{Valid: v.Valid, Error: v.Error, Added: added, Removed: removed})
}

type apiFirewallApplyResp struct {
	RollbackWindowSecs int  `json:"rollback_window_secs"`
	PanelReachable     bool `json:"panel_reachable"`
}

// POST /api/servers/{id}/firewall/apply -- actually applies the rendered
// ruleset with an armed host-side rollback (see installer.sh's
// firewall-apply/protean-fw-rollback timer). Fast (well under a second
// for iptables-restore + guard-inserts), so this is a plain synchronous
// call, not streamed -- there's nothing long-running here to watch live,
// unlike OS-updates-apply.
func (s *Server) apiFirewallApply(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "server manager not configured", "менеджер серверов не настроен"))
		return
	}
	srv, policy, rendered, err := s.renderFor(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	baseline := s.computeBaseline(r.Context(), srv)

	client, closeFn, err := s.mgr.ConsoleClient(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	defer closeFn()

	args := []string{strconv.Itoa(policy.RollbackWindowSecs), strconv.Itoa(srv.Port), criticalPortsCSV(baseline, srv.Port)}
	out, err := runFirewallVerb(r.Context(), client, "firewall-apply", args, rendered)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var applyResp fwApplyJSON
	if err := json.Unmarshal([]byte(out), &applyResp); err != nil || !applyResp.Applied {
		errMsg := applyResp.Error
		if errMsg == "" {
			errMsg = "apply failed: " + out
		}
		writeErr(w, http.StatusBadGateway, errMsg)
		return
	}

	if err := s.store.SetLastApplied(r.Context(), id, rendered, time.Now()); err != nil {
		slog.Error("firewall: SetLastApplied failed", "server", id, "err", err)
	}
	s.audit(r.Context(), "firewall.apply", id)

	writeOK(w, apiFirewallApplyResp{
		RollbackWindowSecs: applyResp.RollbackWindowSecs,
		PanelReachable:     s.probeFreshReachability(r.Context(), id),
	})
}

// probeFreshReachability dials a brand-new SSH connection (never the
// pool) right after an apply, to prove NEW connections actually still
// work -- an already-open pooled stream can keep functioning purely via
// an ESTABLISHED/RELATED accept even when the new rules would refuse any
// new connection attempt, which is exactly the failure mode this exists
// to catch.
func (s *Server) probeFreshReachability(ctx context.Context, serverID string) bool {
	client, closeFn, err := s.mgr.FreshClient(ctx, serverID)
	if err != nil {
		return false
	}
	defer closeFn()
	_, err = client.Run(ctx, "true")
	return err == nil
}

// POST /api/servers/{id}/firewall/confirm -- persists the pending change
// past the rollback window. Always dials a FRESH connection (never the
// pool), for the same reason probeFreshReachability does: confirming over
// an already-open stream would prove nothing about whether new
// connections still work.
func (s *Server) apiFirewallConfirm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "server manager not configured", "менеджер серверов не настроен"))
		return
	}
	client, closeFn, err := s.mgr.FreshClient(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, msg(r, "cannot reach server to confirm -- it may not have recovered from the change", "не удалось подключиться к серверу для подтверждения — возможно, он не восстановился после изменения"))
		return
	}
	defer closeFn()

	out, err := runFirewallVerb(r.Context(), client, "firewall-confirm", nil, "")
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var resp fwConfirmJSON
	if err := json.Unmarshal([]byte(out), &resp); err != nil || !resp.Confirmed {
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = "confirm failed: " + out
		}
		writeErr(w, http.StatusBadGateway, errMsg)
		return
	}
	if err := s.store.SetLastConfirmed(r.Context(), id, time.Now()); err != nil {
		slog.Error("firewall: SetLastConfirmed failed", "server", id, "err", err)
	}
	s.audit(r.Context(), "firewall.confirm", id)
	writeOK(w, nil)
}

// POST /api/servers/{id}/firewall/rollback -- the panic button. Fresh
// connection, same reasoning as confirm.
func (s *Server) apiFirewallRollback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "server manager not configured", "менеджер серверов не настроен"))
		return
	}
	client, closeFn, err := s.mgr.FreshClient(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	defer closeFn()

	out, err := runFirewallVerb(r.Context(), client, "firewall-rollback", nil, "")
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var resp fwRollbackJSON
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		writeErr(w, http.StatusBadGateway, "unparseable rollback response: "+out)
		return
	}
	if resp.Error != "" {
		writeErr(w, http.StatusBadGateway, resp.Error)
		return
	}
	s.audit(r.Context(), "firewall.rollback", id)
	writeOK(w, nil)
}

// GET /api/servers/{id}/firewall/status -- lightweight poll target for the
// UI's countdown banner (pooled connection is fine here; this is purely
// informational, not the safety-critical confirm/rollback check).
func (s *Server) apiFirewallStatusGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "server manager not configured", "менеджер серверов не настроен"))
		return
	}
	client, closeFn, err := s.mgr.ConsoleClient(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	defer closeFn()

	out, err := runFirewallVerb(r.Context(), client, "firewall-status", nil, "")
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var st fwStatusJSON
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		writeErr(w, http.StatusBadGateway, "unparseable status response: "+out)
		return
	}
	writeOK(w, apiFirewallStatus{Pending: st.Pending, RemainingSecs: st.RemainingSecs, ConfirmedStateSaved: st.ConfirmedStateSaved})
}
