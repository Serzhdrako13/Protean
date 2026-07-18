// Package api wires HTTP routes to the panel's auth, store, and vpn
// providers, and renders the html/template UI.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"protean/internal/auth"
	"protean/internal/console"
	"protean/internal/sshexec"
	"protean/internal/store"
	"protean/internal/vpn"
	"protean/internal/web"
	"protean/internal/webtls"
)

// HostProbe exposes one host's SSH reachability and command stats for health
// checks and metrics. Satisfied by *sshexec.Client.
type HostProbe interface {
	Ping(ctx context.Context) error
	Stats() sshexec.Stats
}

type Server struct {
	reg          *vpn.Registry
	store        *store.Store
	auth         *auth.Manager
	enc          *auth.Encryptor
	csrf         *auth.CSRF
	pending      *auth.PendingAuth
	status       *statusCache
	bruteForce   *auth.BruteForceGuard
	metricsToken string
	// installerFor resolves the on-host installer for a server id. Optional
	// (nil in tests); set via SetInstallerFunc.
	installerFor func(serverID string) (*vpn.Installer, bool)
	// mgr (re)builds/removes servers at runtime. Optional (nil in tests).
	mgr ServerManager
	// workers tracks background goroutines so shutdown can join them.
	workers sync.WaitGroup
	// hosts returns the current per-server SSH clients (serverID -> probe),
	// for health checks and command metrics. Optional: nil in tests.
	hosts     func() map[string]HostProbe
	hostHM    sync.Mutex
	hostOK    bool
	hostErr   string
	hostAt    time.Time // when host health was last probed
	hostCheck time.Duration

	// HTTP request metrics (atomic).
	httpReqs   atomic.Uint64
	httpErrs   atomic.Uint64
	httpLastNs atomic.Int64

	// trustProxy: honor X-Forwarded-For for the client IP (behind a proxy).
	trustProxy bool
	// cookieInsecure drops the Secure flag on cookies, so the UI works over
	// plain HTTP (dev / trusted LAN). Off by default: prod sits behind HTTPS.
	cookieInsecure bool

	// tlsMgr manages the panel's own web-listener certificate; nil in tests
	// that don't wire it (the /api/tls* handlers 503 in that case).
	tlsMgr *webtls.Manager

	// vpnSetupDir holds the self-service portal's "how to connect" content
	// (see internal/vpnsetup) -- empty in tests that don't wire it, in
	// which case apiVPNSetupContent falls back to the embedded defaults.
	vpnSetupDir string

	// console backs the web SSH console's ticketing/concurrency limits
	// (internal/console). Optional: nil in tests that don't wire it.
	console *console.Hub
	// consoleAllowedOrigins additionally authorizes WS upgrade Origins
	// beyond the request's own Host -- see config.ConsoleAllowedOrigins.
	consoleAllowedOrigins []string

	// panelPorts are the panel's own reachable ports (web listener + 80/443
	// for ACME), protected by the firewall feature's baseline whenever the
	// target server is flagged as the panel host. Empty in tests that don't
	// wire it.
	panelPorts []int
}

// SetPanelPorts wires the panel's own reachable ports for the firewall
// feature's baseline (see internal/firewall.ComputeBaseline).
func (s *Server) SetPanelPorts(ports []int) { s.panelPorts = ports }

// SetConsoleAllowedOrigins wires extra WS-upgrade Origins to accept beyond
// the request's own Host (reverse-proxy deployments under a different
// browser-facing origin).
func (s *Server) SetConsoleAllowedOrigins(origins []string) { s.consoleAllowedOrigins = origins }

// SetTLSManager wires the panel's own web-TLS certificate manager (see
// internal/webtls) -- required for the /api/tls* settings/status endpoints.
func (s *Server) SetTLSManager(m *webtls.Manager) { s.tlsMgr = m }

// SetVPNSetupDir wires the directory apiVPNSetupContent reads from (see
// internal/vpnsetup) -- a Docker volume mount by convention, so an admin can
// edit the portal's connection instructions without rebuilding the panel.
func (s *Server) SetVPNSetupDir(dir string) { s.vpnSetupDir = dir }

// SetCookieInsecure allows cookies without the Secure flag (plain-HTTP access).
func (s *Server) SetCookieInsecure(v bool) { s.cookieInsecure = v }

// SetTrustProxy controls whether X-Forwarded-For is trusted for the client IP.
func (s *Server) SetTrustProxy(v bool) { s.trustProxy = v }

// SetHostsFunc wires a live view of the per-server SSH clients so /healthz can
// verify reachability and /metrics can report per-server command stats.
func (s *Server) SetHostsFunc(fn func() map[string]HostProbe) {
	s.hosts = fn
	if s.hostCheck == 0 {
		s.hostCheck = 10 * time.Second
	}
}

func (s *Server) hostSet() map[string]HostProbe {
	if s.hosts == nil {
		return nil
	}
	return s.hosts()
}

// hostHealthy reports aggregate host SSH reachability across all servers,
// caching the result for hostCheck to avoid SSH round-trips on every /healthz.
// Healthy means every server responded; the message names the ones that didn't.
func (s *Server) hostHealthy(ctx context.Context) (bool, string) {
	hosts := s.hostSet()
	if len(hosts) == 0 {
		return true, "" // no servers wired (tests / not configured yet)
	}
	s.hostHM.Lock()
	if !s.hostAt.IsZero() && time.Since(s.hostAt) < s.hostCheck {
		ok, msg := s.hostOK, s.hostErr
		s.hostHM.Unlock()
		return ok, msg
	}
	s.hostHM.Unlock()

	var down []string
	for id, h := range hosts {
		if err := h.Ping(ctx); err != nil {
			down = append(down, id+": "+err.Error())
		}
	}
	sort.Strings(down)

	s.hostHM.Lock()
	s.hostOK = len(down) == 0
	s.hostErr = strings.Join(down, "; ")
	s.hostAt = time.Now()
	ok, msg := s.hostOK, s.hostErr
	s.hostHM.Unlock()
	return ok, msg
}

// goWorker runs fn as a tracked background goroutine so WaitWorkers can join it
// on shutdown (fn should return when its ctx is cancelled).
func (s *Server) goWorker(fn func()) {
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		fn()
	}()
}

// WaitWorkers blocks until all background workers have returned or timeout
// elapses. Call after the HTTP server has shut down (ctx already cancelled).
func (s *Server) WaitWorkers(timeout time.Duration) {
	done := make(chan struct{})
	go func() { s.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("shutdown: background workers did not stop within timeout", "timeout", timeout)
	}
}

func NewServer(reg *vpn.Registry, st *store.Store, am *auth.Manager, enc *auth.Encryptor, csrf *auth.CSRF, pending *auth.PendingAuth, metricsToken string) *Server {
	return &Server{
		reg:          reg,
		store:        st,
		auth:         am,
		enc:          enc,
		csrf:         csrf,
		pending:      pending,
		status:       newStatusCache(),
		bruteForce:   auth.NewBruteForceGuard(st),
		metricsToken: metricsToken,
	}
}

// SetInstallerFunc wires per-server installer resolution.
func (s *Server) SetInstallerFunc(fn func(serverID string) (*vpn.Installer, bool)) {
	s.installerFor = fn
}

// ServerManager (re)builds or removes a server's SSH client + providers at
// runtime, so the servers admin page can apply changes live. Satisfied by
// *servers.Manager.
type ServerManager interface {
	Rebuild(ctx context.Context, serverID string) error
	Remove(serverID string)
	// ConsoleClient resolves a live SSH client for the web SSH console,
	// preferring an already-pooled connection and falling back to an
	// ephemeral one (see servers.Manager.ConsoleClient's doc comment). The
	// returned close func must be called exactly once when the console
	// session ends.
	ConsoleClient(ctx context.Context, serverID string) (*sshexec.Client, func(), error)
	// FreshClient always dials a brand-new connection, never the pool --
	// used to verify reachability right after a firewall change (see
	// servers.Manager.FreshClient's doc comment for why reusing the pool
	// there would prove nothing).
	FreshClient(ctx context.Context, serverID string) (*sshexec.Client, func(), error)
}

// SetServerManager wires runtime server (re)build/remove.
func (s *Server) SetServerManager(m ServerManager) { s.mgr = m }

// SetConsoleHub wires the web SSH console's session/ticket bookkeeping
// (internal/console). Optional: the /api/console/* handlers 503 if unset.
func (s *Server) SetConsoleHub(h *console.Hub) { s.console = h }

// serverOf returns the server id encoded in a provider instance key
// "server:instance"; empty if unscoped.
func serverOf(providerKey string) string {
	if i := strings.IndexByte(providerKey, ':'); i >= 0 {
		return providerKey[:i]
	}
	return ""
}

// installerForProvider resolves the installer for the server owning a provider
// instance key.
func (s *Server) installerForProvider(providerKey string) (*vpn.Installer, bool) {
	if s.installerFor == nil {
		return nil, false
	}
	return s.installerFor(serverOf(providerKey))
}

// providerStatus returns a provider's status via the short-TTL cache. Falls
// back to a direct call if no cache is configured (e.g. in tests).
func (s *Server) providerStatus(ctx context.Context, prov vpn.Provider) (vpn.ServerStatus, error) {
	if s.status == nil {
		return prov.Status(ctx)
	}
	return s.status.get(ctx, prov)
}

// providerPeers returns a provider's peer list via the short-TTL cache. Falls
// back to a direct call if no cache is configured (e.g. in tests).
func (s *Server) providerPeers(ctx context.Context, prov vpn.Provider) ([]vpn.Peer, error) {
	if s.status == nil {
		return prov.ListPeers(ctx)
	}
	return s.status.getPeers(ctx, prov)
}

// invalidateStatus drops a provider's cached status (nil-safe for tests).
func (s *Server) invalidateStatus(name string) {
	if s.status != nil {
		s.status.invalidate(name)
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /assets/", web.SPAAssetsHandler())
	mux.Handle("GET /fonts/", web.SPAFontsHandler())

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /license.txt", s.handleLicense)

	// SPA login page (static, separate Vite entry). Logout is client-side
	// only now (POST /api/logout) — the old server-rendered nav that posted
	// to /logout is gone. Both the bare path and its trailing-slash variant
	// are registered explicitly -- Go's ServeMux treats "/login" as an exact
	// match only, so "/login/" would otherwise silently fall through to the
	// "GET /" SPA catch-all below, serving the ADMIN bundle at that URL
	// instead of the login page. The admin bundle's client-side router has
	// no route for "/login"/"/portal", so that fallthrough surfaces as
	// react-router's raw "Unexpected Application Error! 404" screen.
	mux.HandleFunc("GET /login", web.ServeLoginHTML)
	mux.HandleFunc("GET /login/", web.ServeLoginHTML)

	// Self-service portal — a third standalone entry (own login, no sidebar).
	// A role=="user" session never reaches the admin SPA (see requireAuthAPI's
	// role gate); this is the only page it can use. See the /login comment
	// above for why both path forms are registered.
	mux.HandleFunc("GET /portal", web.ServePortalHTML)
	mux.HandleFunc("GET /portal/", web.ServePortalHTML)

	// ===== JSON API (SPA) =====
	mux.HandleFunc("GET /api/csrf", s.apiCSRF)
	mux.HandleFunc("POST /api/login", s.apiLogin)
	mux.HandleFunc("POST /api/login/2fa", s.apiLogin2FA)
	mux.HandleFunc("POST /api/logout", s.requireAuthAPI(s.apiLogout))
	mux.HandleFunc("GET /api/auth-methods/enabled", s.apiAuthMethodsEnabled)
	mux.HandleFunc("GET /api/auth/oidc/start", s.apiOIDCStart)
	mux.HandleFunc("GET /api/auth/oidc/callback", s.apiOIDCCallback)

	mux.HandleFunc("GET /api/auth-methods/internal", s.requireAuthAPI(s.apiInternalAuthGet))
	mux.HandleFunc("PUT /api/auth-methods/internal", s.requireAuthAPI(s.apiInternalAuthUpdate))
	mux.HandleFunc("GET /api/auth-methods/ldap", s.requireAuthAPI(s.apiLDAPSettingsGet))
	mux.HandleFunc("PUT /api/auth-methods/ldap", s.requireAuthAPI(s.apiLDAPSettingsUpdate))
	mux.HandleFunc("POST /api/auth-methods/ldap/test", s.requireAuthAPI(s.apiLDAPSettingsTest))
	mux.HandleFunc("GET /api/auth-methods/oidc", s.requireAuthAPI(s.apiOIDCSettingsGet))
	mux.HandleFunc("PUT /api/auth-methods/oidc", s.requireAuthAPI(s.apiOIDCSettingsUpdate))
	mux.HandleFunc("POST /api/auth-methods/oidc/test", s.requireAuthAPI(s.apiOIDCSettingsTest))
	mux.HandleFunc("GET /api/auth-methods/groups", s.requireAuthAPI(s.apiAuthGroupRulesList))
	mux.HandleFunc("POST /api/auth-methods/groups", s.requireAuthAPI(s.apiAuthGroupRulesAdd))
	mux.HandleFunc("DELETE /api/auth-methods/groups", s.requireAuthAPI(s.apiAuthGroupRulesDelete))

	mux.HandleFunc("GET /api/account", s.requireAuthAPI(s.apiAccountGet))
	mux.HandleFunc("POST /api/account", s.requireAuthAPI(s.apiAccountUpdate))
	mux.HandleFunc("PUT /api/account/language", s.requireAuthAPI(s.apiAccountUpdateLanguage))
	mux.HandleFunc("POST /api/account/2fa/setup", s.requireAuthAPI(s.apiTOTPSetup))
	mux.HandleFunc("POST /api/account/2fa/enable", s.requireAuthAPI(s.apiTOTPEnable))
	mux.HandleFunc("POST /api/account/2fa/disable", s.requireAuthAPI(s.apiTOTPDisable))

	mux.HandleFunc("GET /api/dashboard", s.requireAuthAPI(s.apiDashboard))

	mux.HandleFunc("GET /api/servers", s.requireAuthAPI(s.apiServersList))
	mux.HandleFunc("POST /api/servers", s.requireAuthAPI(s.apiServersCreate))
	mux.HandleFunc("POST /api/ssh/probe-host-key", s.requireAuthAPI(s.apiProbeHostKey))
	mux.HandleFunc("PUT /api/servers/{id}", s.requireAuthAPI(s.apiServersUpdate))
	mux.HandleFunc("DELETE /api/servers/{id}", s.requireAuthAPI(s.apiServersDelete))
	mux.HandleFunc("POST /api/servers/{id}/enabled", s.requireAuthAPI(s.apiServersSetEnabled))
	mux.HandleFunc("GET /api/servers/{id}/instances", s.requireAuthAPI(s.apiServerInstancesList))
	mux.HandleFunc("POST /api/servers/{id}/instances", s.requireAuthAPI(s.apiServerInstancesCreate))
	mux.HandleFunc("PUT /api/servers/{id}/instances/{name}", s.requireAuthAPI(s.apiServerInstancesUpdateLabel))
	mux.HandleFunc("PUT /api/servers/{id}/instances/{name}/visibility", s.requireAuthAPI(s.apiServerInstancesUpdateVisibility))
	mux.HandleFunc("PUT /api/servers/{id}/instances/{name}/description", s.requireAuthAPI(s.apiServerInstancesUpdateDescription))
	mux.HandleFunc("DELETE /api/servers/{id}/instances/{name}", s.requireAuthAPI(s.apiServerInstancesDelete))
	mux.HandleFunc("GET /api/servers/{id}/traffic", s.requireAuthAPI(s.apiServerTrafficAggregate))
	mux.HandleFunc("GET /api/servers/{id}/updates", s.requireAuthAPI(s.apiServerUpdatesCheck))
	mux.HandleFunc("POST /api/servers/{id}/updates/apply", s.requireAuthAPI(s.apiServerUpdatesApply))

	mux.HandleFunc("GET /api/servers/{id}/firewall", s.requireAuthAPI(s.apiFirewallGet))
	mux.HandleFunc("PUT /api/servers/{id}/firewall/policy", s.requireAuthAPI(s.apiFirewallPolicyPut))
	mux.HandleFunc("PUT /api/servers/{id}/firewall/rules", s.requireAuthAPI(s.apiFirewallRulesPut))
	mux.HandleFunc("POST /api/servers/{id}/firewall/dry-run", s.requireAuthAPI(s.apiFirewallDryRun))
	mux.HandleFunc("POST /api/servers/{id}/firewall/apply", s.requireAuthAPI(s.apiFirewallApply))
	mux.HandleFunc("POST /api/servers/{id}/firewall/confirm", s.requireAuthAPI(s.apiFirewallConfirm))
	mux.HandleFunc("POST /api/servers/{id}/firewall/rollback", s.requireAuthAPI(s.apiFirewallRollback))
	mux.HandleFunc("GET /api/servers/{id}/firewall/status", s.requireAuthAPI(s.apiFirewallStatusGet))

	mux.HandleFunc("GET /api/console/targets", s.requireAuthAPI(s.apiConsoleTargets))
	mux.HandleFunc("POST /api/console/sessions", s.requireAuthAPI(s.apiConsoleSessionCreate))
	mux.HandleFunc("GET /api/console/ws", s.apiConsoleWS) // ticket-authenticated, not cookie/CSRF -- see serveConsoleBridge
	mux.HandleFunc("GET /api/console/updates-ws", s.apiConsoleUpdatesWS)
	mux.HandleFunc("GET /api/console/panel-host", s.requireAuthAPI(s.apiConsolePanelHostGet))
	mux.HandleFunc("PUT /api/console/panel-host", s.requireAuthAPI(s.apiConsolePanelHostSet))

	mux.HandleFunc("GET /api/install", s.requireAuthAPI(s.apiInstallStatus))
	mux.HandleFunc("POST /api/install/{provider}", s.requireAuthAPI(s.apiInstallProvider))

	mux.HandleFunc("GET /api/providers", s.requireAuthAPI(s.apiProvidersList))
	mux.HandleFunc("GET /api/providers/{provider}", s.requireAuthAPI(s.apiProviderDetail))
	mux.HandleFunc("GET /api/providers/{provider}/traffic", s.requireAuthAPI(s.apiProviderTraffic))
	mux.HandleFunc("POST /api/providers/{provider}/setup", s.requireAuthAPI(s.apiProviderSetup))

	mux.HandleFunc("GET /api/providers/{provider}/server-config", s.requireAuthAPI(s.apiServerConfigGet))
	mux.HandleFunc("PUT /api/providers/{provider}/server-config", s.requireAuthAPI(s.apiServerConfigUpdate))
	mux.HandleFunc("GET /api/providers/{provider}/mesh-settings", s.requireAuthAPI(s.apiMeshSettingsGet))
	mux.HandleFunc("PUT /api/providers/{provider}/mesh-settings", s.requireAuthAPI(s.apiMeshSettingsUpdate))
	mux.HandleFunc("GET /api/providers/{provider}/logs", s.requireAuthAPI(s.apiServiceLogsGet))
	mux.HandleFunc("POST /api/providers/{provider}/service", s.requireAuthAPI(s.apiServiceAction))
	mux.HandleFunc("GET /api/providers/{provider}/ca", s.requireAuthAPI(s.apiCAInfo))
	mux.HandleFunc("POST /api/providers/{provider}/ca", s.requireAuthAPI(s.apiCAImport))
	mux.HandleFunc("GET /api/providers/{provider}/backups", s.requireAuthAPI(s.apiBackupsList))
	mux.HandleFunc("POST /api/providers/{provider}/backups/{id}/restore", s.requireAuthAPI(s.apiRestoreBackup))

	mux.HandleFunc("GET /api/providers/{provider}/xray", s.requireAuthAPI(s.apiXrayGet))
	mux.HandleFunc("POST /api/providers/{provider}/xray", s.requireAuthAPI(s.apiXrayApply))
	mux.HandleFunc("POST /api/providers/{provider}/xray/clients", s.requireAuthAPI(s.apiXrayAddClient))
	mux.HandleFunc("POST /api/providers/{provider}/xray/clients/remove", s.requireAuthAPI(s.apiXrayRemoveClient))
	mux.HandleFunc("GET /api/providers/{provider}/xray/sub", s.requireAuthAPI(s.handleXraySubscription))
	mux.HandleFunc("GET /api/providers/{provider}/xray/qr", s.requireAuthAPI(s.handleXrayQR))
	mux.HandleFunc("GET /api/traffic/aggregate", s.requireAuthAPI(s.apiTrafficAggregate))

	mux.HandleFunc("POST /api/providers/{provider}/peers", s.requireAuthAPI(s.apiCreatePeer))
	mux.HandleFunc("POST /api/providers/{provider}/peers/import", s.requireAuthAPI(s.apiImportPeer))
	mux.HandleFunc("PUT /api/providers/{provider}/peers/{id}", s.requireAuthAPI(s.apiUpdatePeer))
	mux.HandleFunc("DELETE /api/providers/{provider}/peers/{id}", s.requireAuthAPI(s.apiDeletePeer))
	mux.HandleFunc("POST /api/providers/{provider}/peers/{id}/disable", s.requireAuthAPI(s.apiDisablePeer))
	mux.HandleFunc("POST /api/providers/{provider}/peers/{id}/enable", s.requireAuthAPI(s.apiEnablePeer))
	mux.HandleFunc("POST /api/providers/{provider}/peers/{id}/rotate", s.requireAuthAPI(s.apiRotatePeer))
	mux.HandleFunc("POST /api/providers/{provider}/peers/{id}/mute", s.requireAuthAPI(s.apiTogglePeerMute))
	mux.HandleFunc("GET /api/providers/{provider}/peers/{id}/config", s.requireAuthAPI(s.handlePeerConfig))
	mux.HandleFunc("GET /api/providers/{provider}/peers/{id}/config/text", s.requireAuthAPI(s.apiPeerConfigText))
	mux.HandleFunc("GET /api/providers/{provider}/peers/{id}/qr", s.requireAuthAPI(s.handlePeerQR))
	mux.HandleFunc("POST /api/providers/{provider}/peers/{id}/owner", s.requireAuthAPI(s.apiPeerSetOwner))
	mux.HandleFunc("POST /api/providers/{provider}/peers/{id}/node-owner", s.requireAuthAPI(s.apiPeerSetNodeOwner))

	mux.HandleFunc("GET /api/mesh", s.requireAuthAPI(s.apiMeshGet))
	mux.HandleFunc("POST /api/mesh/providers/{provider}/forwarding", s.requireAuthAPI(s.apiMeshEnableForwarding))

	mux.HandleFunc("GET /api/clients", s.requireAuthAPI(s.apiClientsList))
	mux.HandleFunc("GET /api/nodes", s.requireAuthAPI(s.apiNodesList))
	mux.HandleFunc("POST /api/nodes", s.requireAuthAPI(s.apiNodesCreate))
	mux.HandleFunc("PUT /api/nodes/{id}", s.requireAuthAPI(s.apiNodesUpdate))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.requireAuthAPI(s.apiNodesDelete))
	mux.HandleFunc("GET /api/nodes/{id}/access", s.requireAuthAPI(s.apiNodeAccessList))
	mux.HandleFunc("POST /api/nodes/{id}/access/{provider}", s.requireAuthAPI(s.apiNodeAccessSet))

	mux.HandleFunc("GET /api/subnets", s.requireAuthAPI(s.apiSubnetsList))
	mux.HandleFunc("POST /api/subnets", s.requireAuthAPI(s.apiSubnetsCreate))
	mux.HandleFunc("DELETE /api/subnets/{id}", s.requireAuthAPI(s.apiSubnetsDelete))

	mux.HandleFunc("GET /api/audit", s.requireAuthAPI(s.apiAuditList))

	mux.HandleFunc("GET /api/users", s.requireAuthAPI(s.apiUsersList))
	mux.HandleFunc("POST /api/users", s.requireAuthAPI(s.apiUsersCreate))
	mux.HandleFunc("DELETE /api/users/{id}", s.requireAuthAPI(s.apiUsersDelete))
	mux.HandleFunc("POST /api/users/{id}/reset-password", s.requireAuthAPI(s.apiUsersResetPassword))
	mux.HandleFunc("POST /api/users/{id}/enabled", s.requireAuthAPI(s.apiUsersSetEnabled))
	mux.HandleFunc("POST /api/users/{id}/portal-access", s.requireAuthAPI(s.apiUsersSetPortalAccess))
	mux.HandleFunc("GET /api/users/{id}/access", s.requireAuthAPI(s.apiUserAccessList))
	mux.HandleFunc("POST /api/users/{id}/access/{provider}", s.requireAuthAPI(s.apiUserAccessSet))

	mux.HandleFunc("GET /api/access-requests", s.requireAuthAPI(s.apiAccessRequestsList))
	mux.HandleFunc("POST /api/access-requests/{id}/approve", s.requireAuthAPI(s.apiAccessRequestApprove))
	mux.HandleFunc("POST /api/access-requests/{id}/deny", s.requireAuthAPI(s.apiAccessRequestDeny))
	mux.HandleFunc("DELETE /api/access-requests/{id}", s.requireAuthAPI(s.apiAccessRequestDelete))
	mux.HandleFunc("POST /api/access-requests/clear-denied", s.requireAuthAPI(s.apiAccessRequestClearDenied))

	// Admin's own overview of every assigned peer across every instance,
	// including ones hidden from the self-service portal (portal_visible =
	// false) -- reuses buildPeerDownload/buildPeerQRPNG, no duplicate logic.
	mux.HandleFunc("GET /api/admin-portal", s.requireAuthAPI(s.apiAdminPortalList))
	mux.HandleFunc("GET /api/admin-portal/peers/{provider}/{key}/config", s.requireAuthAPI(s.apiAdminPortalPeerConfig))
	mux.HandleFunc("GET /api/admin-portal/peers/{provider}/{key}/qr", s.requireAuthAPI(s.apiAdminPortalPeerQR))

	// ===== Self-service portal (role=="user" is confined to these +
	// /api/account* + /api/logout by requireAuthAPI's role gate) =====
	mux.HandleFunc("GET /api/portal/me", s.requireAuthAPI(s.apiPortalMe))
	mux.HandleFunc("GET /api/portal/password-policy", s.requireAuthAPI(s.apiPortalPasswordPolicy))
	mux.HandleFunc("POST /api/portal/requests", s.requireAuthAPI(s.apiPortalRequestAccess))
	mux.HandleFunc("GET /api/portal/peers/{provider}/{key}/config", s.requireAuthAPI(s.apiPortalPeerConfig))
	mux.HandleFunc("GET /api/portal/peers/{provider}/{key}/config/text", s.requireAuthAPI(s.apiPortalPeerConfigText))
	mux.HandleFunc("GET /api/portal/peers/{provider}/{key}/qr", s.requireAuthAPI(s.apiPortalPeerQR))
	mux.HandleFunc("GET /api/portal/connection-history", s.requireAuthAPI(s.apiPortalConnectionHistory))
	mux.HandleFunc("GET /api/portal/vpn-setup-content", s.requireAuthAPI(s.apiVPNSetupContent))

	mux.HandleFunc("GET /api/tls", s.requireAuthAPI(s.apiTLSGet))
	mux.HandleFunc("PUT /api/tls", s.requireAuthAPI(s.apiTLSUpdate))
	mux.HandleFunc("POST /api/tls/self-signed/reissue", s.requireAuthAPI(s.apiTLSReissueSelfSigned))

	mux.HandleFunc("GET /api/login-security/settings", s.requireAuthAPI(s.apiLoginSecuritySettingsGet))
	mux.HandleFunc("PUT /api/login-security/settings", s.requireAuthAPI(s.apiLoginSecuritySettingsUpdate))
	mux.HandleFunc("GET /api/login-security/ip-rules", s.requireAuthAPI(s.apiLoginIPRulesList))
	mux.HandleFunc("POST /api/login-security/ip-rules", s.requireAuthAPI(s.apiLoginIPRulesAdd))
	mux.HandleFunc("DELETE /api/login-security/ip-rules", s.requireAuthAPI(s.apiLoginIPRulesDelete))
	mux.HandleFunc("GET /api/login-security/bans", s.requireAuthAPI(s.apiLoginBansList))
	mux.HandleFunc("POST /api/login-security/bans/unban", s.requireAuthAPI(s.apiLoginBansUnban))
	mux.HandleFunc("GET /api/login-security/stats", s.requireAuthAPI(s.apiLoginSecurityStats))

	mux.HandleFunc("GET /api/password-policy/settings", s.requireAuthAPI(s.apiPasswordPolicyGet))
	mux.HandleFunc("PUT /api/password-policy/settings", s.requireAuthAPI(s.apiPasswordPolicyUpdate))

	mux.HandleFunc("GET /api/data-retention/settings", s.requireAuthAPI(s.apiDataRetentionGet))
	mux.HandleFunc("PUT /api/data-retention/settings", s.requireAuthAPI(s.apiDataRetentionUpdate))
	mux.HandleFunc("POST /api/data-retention/cleanup", s.requireAuthAPI(s.apiDataRetentionCleanupNow))

	mux.HandleFunc("GET /api/connection-history", s.requireAuthAPI(s.apiConnectionHistoryList))
	mux.HandleFunc("GET /api/zabbix/template", s.requireAuthAPI(s.apiZabbixTemplateDownload))

	mux.HandleFunc("GET /api/notifications", s.requireAuthAPI(s.apiNotifyGet))
	mux.HandleFunc("POST /api/notifications/settings", s.requireAuthAPI(s.apiNotifySettingsUpdate))
	mux.HandleFunc("POST /api/notifications/channel/{kind}", s.requireAuthAPI(s.apiNotifyChannelUpdate))
	mux.HandleFunc("POST /api/notifications/channel/{kind}/test", s.requireAuthAPI(s.apiNotifyChannelTest))

	// SPA fallback: any path not matched above (client-side routes like
	// /servers, /providers/{provider}, etc.) gets the SPA shell; React
	// Router resolves the rest. No server-side auth gate here — each page's
	// own API calls 401 and the SPA redirects to /login client-side.
	mux.HandleFunc("GET /", web.ServeIndexHTML)

	return s.withMetrics(mux)
}

// withMetrics wraps the handler to count requests, server errors (status >=
// 500) and the last request duration, exposed on /metrics.
func (s *Server) withMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.httpReqs.Add(1)
		s.httpLastNs.Store(int64(time.Since(start)))
		if rec.status >= 500 {
			s.httpErrs.Add(1)
		}
	})
}

// statusRecorder captures the response status code for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// httpStats returns request count, server-error count and last request latency.
func (s *Server) httpStats() (reqs, errs uint64, last time.Duration) {
	return s.httpReqs.Load(), s.httpErrs.Load(), time.Duration(s.httpLastNs.Load())
}
