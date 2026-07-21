// Package servers builds and maintains the per-server SSH clients and VPN
// provider instances from the DB `servers` table, keeping the shared vpn
// registry in sync as servers are added, updated or removed at runtime.
package servers

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"protean/internal/auth"
	"protean/internal/sshexec"
	"protean/internal/store"
	"protean/internal/vpn"
	"protean/internal/vpn/amneziawg"
	"protean/internal/vpn/ikev2"
	"protean/internal/vpn/openvpn"
	"protean/internal/vpn/wireguard"
	"protean/internal/vpn/xray"
)

// Template is the legacy env-var-configured instance set, used ONLY to seed
// a server's row in `server_instances` the first time it's ever built (so
// existing deployments migrate transparently without re-entering config).
// After seeding, `server_instances` is authoritative and per-server
// (see internal/store/server_instances.go) — new instances are added/removed
// per server via the API, not by editing env vars.
type Template struct {
	WGInterfaces      []string
	AWGInterfaces     []string
	OpenVPNInstance   string
	OpenVPNListenPort int
	OpenVPNProto      string
	OpenVPNServerNet  string
	OpenVPNServerMask string
	IKEv2Pool         string
	IKEv2DNS          string
	SSHTimeout        time.Duration
	SSHCmdTimeout     time.Duration
}

// singleInstanceTypes are provider types with no per-instance host-side
// isolation today: ikev2 shares one strongSwan daemon per server regardless
// of connection name (restarting one restarts all), and xray's installer
// only sets up a single systemd unit + config path. Capped at 1 until the
// installer script grows per-instance systemd templating for these two.
var singleInstanceTypes = map[string]bool{"ikev2": true, "xray": true}

// Manager owns the SSH client pool and keeps the registry populated.
type Manager struct {
	store *store.Store
	enc   *auth.Encryptor
	reg   *vpn.Registry
	tmpl  Template

	mu         sync.Mutex
	clients    map[string]*sshexec.Client // serverID -> ssh
	installers map[string]*vpn.Installer  // serverID -> installer
	names      map[string][]string        // serverID -> registered instance names
}

func NewManager(st *store.Store, enc *auth.Encryptor, reg *vpn.Registry, tmpl Template) *Manager {
	return &Manager{
		store:      st,
		enc:        enc,
		reg:        reg,
		tmpl:       tmpl,
		clients:    map[string]*sshexec.Client{},
		installers: map[string]*vpn.Installer{},
		names:      map[string][]string{},
	}
}

// LoadAll builds providers for every server in the DB. Errors on individual
// servers are returned joined but don't stop the others.
func (m *Manager) LoadAll(ctx context.Context) error {
	list, err := m.store.ListServers(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, srv := range list {
		if !srv.Enabled {
			// Disabled servers stay in the DB with all their instances/
			// settings intact, but the panel never connects to them until
			// re-enabled -- skip rather than Rebuild.
			continue
		}
		if err := m.Rebuild(ctx, srv.ID); err != nil {
			errs = append(errs, fmt.Errorf("server %s: %w", srv.ID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// Rebuild (re)constructs one server's SSH client + providers and swaps them
// into the registry, replacing any previous instances for that server.
func (m *Manager) Rebuild(ctx context.Context, serverID string) error {
	srv, err := m.store.GetServer(ctx, serverID)
	if err != nil {
		return err
	}
	if !srv.Enabled {
		// A disabled server must never get a live SSH connection/providers,
		// regardless of which caller triggers a rebuild (editing its config,
		// a stray retry, etc.) -- Remove is a no-op if it wasn't registered.
		m.Remove(serverID)
		return nil
	}
	keyPEM, err := m.enc.Open(srv.EncKeyPEM)
	if err != nil {
		return fmt.Errorf("decrypt ssh key: %w", err)
	}
	ssh, err := sshexec.New(sshexec.Config{
		Host: srv.Host, Port: srv.Port, User: srv.SSHUser,
		KeyPEM: []byte(keyPEM), HostKey: srv.HostKey,
		Timeout: m.tmpl.SSHTimeout, CmdTimeout: m.tmpl.SSHCmdTimeout,
	})
	if err != nil {
		return err
	}

	providers, names, err := m.buildProviders(ctx, srv, ssh)
	if err != nil {
		return err
	}

	m.mu.Lock()
	// Drop old instances/client for this server first.
	for _, n := range m.names[serverID] {
		m.reg.Unregister(n)
	}
	if old := m.clients[serverID]; old != nil {
		_ = old.Close()
	}
	for _, p := range providers {
		m.reg.Register(p)
	}
	m.clients[serverID] = ssh
	m.installers[serverID] = vpn.NewInstaller(ssh)
	m.names[serverID] = names
	m.mu.Unlock()
	return nil
}

// Remove deregisters a server's providers and closes its SSH client.
func (m *Manager) Remove(serverID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.names[serverID] {
		m.reg.Unregister(n)
	}
	if c := m.clients[serverID]; c != nil {
		_ = c.Close()
	}
	delete(m.clients, serverID)
	delete(m.installers, serverID)
	delete(m.names, serverID)
}

// Installer returns the installer for a server id.
func (m *Manager) Installer(serverID string) (*vpn.Installer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.installers[serverID]
	return inst, ok
}

// CloseAll closes every SSH client (shutdown).
func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.clients {
		_ = c.Close()
	}
}

// Hosts returns a snapshot of serverID -> SSH client for health/metrics.
func (m *Manager) Hosts() map[string]*sshexec.Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]*sshexec.Client, len(m.clients))
	for id, c := range m.clients {
		out[id] = c
	}
	return out
}

// ConsoleClient returns an SSH client suitable for opening an interactive
// console to serverID, for the web SSH console feature. It prefers the
// already-live pooled connection (enabled VPN nodes) -- the "free" path,
// reusing the exact same warm, host-key-pinned client every other provider
// call uses. If there's no pooled client (a panel-host-only row that
// carries no VPN instances, or a disabled row that's still flagged as the
// panel host), it dials a fresh, ephemeral one instead.
//
// The returned close func is the caller's responsibility to invoke exactly
// once when the console session ends: for the pooled path it's a no-op
// (Manager still owns that client's lifecycle); for the ephemeral path it
// closes the connection this call opened, so a console session never
// leaks a connection the pool doesn't know about.
func (m *Manager) ConsoleClient(ctx context.Context, serverID string) (client *sshexec.Client, closeFn func(), err error) {
	m.mu.Lock()
	pooled := m.clients[serverID]
	m.mu.Unlock()
	if pooled != nil {
		return pooled, func() {}, nil
	}
	return m.dialEphemeral(ctx, serverID)
}

// FreshClient ALWAYS dials a brand-new SSH connection, never reusing the
// pool -- used specifically to verify reachability right after a firewall
// change. Reusing an already-open pooled connection there would prove
// nothing: an existing TCP stream can keep working purely via an
// ESTABLISHED/RELATED accept even when the new rules would refuse any NEW
// connection attempt, which is exactly the failure mode this check exists
// to catch.
func (m *Manager) FreshClient(ctx context.Context, serverID string) (client *sshexec.Client, closeFn func(), err error) {
	return m.dialEphemeral(ctx, serverID)
}

func (m *Manager) dialEphemeral(ctx context.Context, serverID string) (*sshexec.Client, func(), error) {
	srv, err := m.store.GetServer(ctx, serverID)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := m.enc.Open(srv.EncKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt ssh key: %w", err)
	}
	ssh, err := sshexec.New(sshexec.Config{
		Host: srv.Host, Port: srv.Port, User: srv.SSHUser,
		KeyPEM: []byte(keyPEM), HostKey: srv.HostKey,
		Timeout: m.tmpl.SSHTimeout, CmdTimeout: m.tmpl.SSHCmdTimeout,
	})
	if err != nil {
		return nil, nil, err
	}
	return ssh, func() { _ = ssh.Close() }, nil
}

// seedInstancesFromTemplate persists the legacy env-var Template as this
// server's initial `server_instances` rows — runs once, only when the
// server has zero rows (fresh server, or a pre-migration deployment seeing
// its first Rebuild after upgrading to per-server instances).
func (m *Manager) seedInstancesFromTemplate(ctx context.Context, serverID string) error {
	var toCreate []store.ServerInstance
	for _, iface := range m.tmpl.WGInterfaces {
		toCreate = append(toCreate, store.ServerInstance{ServerID: serverID, LocalName: iface, Type: "wireguard"})
	}
	for _, iface := range m.tmpl.AWGInterfaces {
		toCreate = append(toCreate, store.ServerInstance{ServerID: serverID, LocalName: iface, Type: "amneziawg"})
	}
	if m.tmpl.OpenVPNInstance != "" {
		toCreate = append(toCreate, store.ServerInstance{
			ServerID: serverID, LocalName: m.tmpl.OpenVPNInstance, Type: "openvpn",
			Config: map[string]string{
				"listen_port": strconv.Itoa(m.tmpl.OpenVPNListenPort),
				"proto":       m.tmpl.OpenVPNProto,
				"server_net":  m.tmpl.OpenVPNServerNet,
				"server_mask": m.tmpl.OpenVPNServerMask,
			},
		})
	}
	toCreate = append(toCreate, store.ServerInstance{
		ServerID: serverID, LocalName: "ikev2", Type: "ikev2",
		Config: map[string]string{"pool": m.tmpl.IKEv2Pool, "dns": m.tmpl.IKEv2DNS},
	})
	toCreate = append(toCreate, store.ServerInstance{ServerID: serverID, LocalName: "xray", Type: "xray"})

	for _, inst := range toCreate {
		if err := m.store.CreateServerInstance(ctx, inst); err != nil {
			return fmt.Errorf("seed instance %s/%s: %w", inst.Type, inst.LocalName, err)
		}
	}
	return nil
}

// buildProviders constructs one server's provider instances from its DB-
// backed `server_instances` rows (seeded from the legacy Template on first
// use), scoping every instance key as "<serverID>:<localName>".
func (m *Manager) buildProviders(ctx context.Context, srv store.Server, ssh *sshexec.Client) ([]vpn.Provider, []string, error) {
	publicHost := srv.PublicHost
	if publicHost == "" {
		publicHost = srv.Host
	}
	scope := func(local string) string { return srv.ID + ":" + local }

	instances, err := m.store.ListServerInstances(ctx, srv.ID)
	if err != nil {
		return nil, nil, err
	}
	// Auto-seeding from the legacy env-var Template is ONLY correct for
	// "default" -- the one server seedDefaultServer (cmd/panel/main.go)
	// creates from SSH_HOST/etc on a pre-multi-server upgrade, where
	// silently populating wg0/awg0/openvpn/ikev2/xray from those env vars
	// is exactly what keeps that deployment working transparently. Any
	// OTHER server (added later via the UI, with any other ID) must start
	// with ZERO instances -- confirmed live this was a real bug: adding a
	// server purely for SSH-based management (console/updates/firewall,
	// or a mesh participant that isn't meant to be a Protean-managed VPN
	// endpoint at all) silently grew a full 5-provider set from the
	// Template's defaults, which then made the dashboard count it as an
	// "online VPN server" even though the admin never asked for that.
	// The admin adds whichever instances they actually want via the
	// existing per-server "Add instance" UI -- same as a panel-host row
	// already only grows instances the operator explicitly adds.
	if len(instances) == 0 && !srv.PanelHost && srv.ID == "default" {
		if err := m.seedInstancesFromTemplate(ctx, srv.ID); err != nil {
			return nil, nil, err
		}
		instances, err = m.store.ListServerInstances(ctx, srv.ID)
		if err != nil {
			return nil, nil, err
		}
	}

	var providers []vpn.Provider
	for _, inst := range instances {
		switch inst.Type {
		case "wireguard":
			providers = append(providers, wireguard.New(ssh, scope(inst.LocalName), inst.LocalName,
				"/etc/wireguard/"+inst.LocalName+".conf", publicHost, m.store))
		case "amneziawg":
			providers = append(providers, amneziawg.New(ssh, scope(inst.LocalName), inst.LocalName,
				"/etc/amnezia/amneziawg/"+inst.LocalName+".conf", publicHost, m.store))
		case "openvpn":
			port, _ := strconv.Atoi(inst.Config["listen_port"])
			if port == 0 {
				port = m.tmpl.OpenVPNListenPort
			}
			proto := inst.Config["proto"]
			if proto == "" {
				proto = m.tmpl.OpenVPNProto
			}
			net := inst.Config["server_net"]
			if net == "" {
				net = m.tmpl.OpenVPNServerNet
			}
			mask := inst.Config["server_mask"]
			if mask == "" {
				mask = m.tmpl.OpenVPNServerMask
			}
			mtu, _ := strconv.Atoi(inst.Config["mtu"])
			mssfix, _ := strconv.Atoi(inst.Config["mssfix"])
			providers = append(providers, openvpn.New(openvpn.Options{
				Instance:    scope(inst.LocalName),
				Interface:   inst.LocalName,
				ConfPath:    "/etc/openvpn/server/" + inst.LocalName + ".conf",
				ServerDir:   "/etc/openvpn/server",
				CCDDir:      "/etc/openvpn/server/ccd-" + inst.LocalName,
				StatusPath:  "/run/openvpn-server/status-" + inst.LocalName + ".log",
				ServiceName: "openvpn-server@" + inst.LocalName,
				PublicHost:  publicHost,
				ListenPort:  port,
				Proto:       proto,
				ServerNet:   net,
				ServerMask:  mask,
				MTU:         mtu,
				Mssfix:      mssfix,
				SSH:         ssh,
				Store:       openvpn.StoreAdapter{S: m.store},
				Enc:         m.enc,
			}))
		case "ikev2":
			pool := inst.Config["pool"]
			if pool == "" {
				pool = m.tmpl.IKEv2Pool
			}
			dns := inst.Config["dns"]
			if dns == "" {
				dns = m.tmpl.IKEv2DNS
			}
			providers = append(providers, ikev2.New(ikev2.Options{
				Instance:   scope(inst.LocalName),
				ConnName:   inst.LocalName,
				SwanctlDir: "/etc/swanctl",
				// "ipsec" (not "strongswan"): the traditional strongSwan
				// service alias present across distros -- some strongSwan
				// packagings (e.g. Ubuntu 24.04) ship the real unit as
				// strongswan-starter.service with no bare "strongswan.service"
				// at all, but systemd resolves the "ipsec" Alias= to whatever
				// the real unit is named either way (confirmed live:
				// `systemctl enable --now ipsec` correctly enables/starts
				// strongswan-starter.service on Ubuntu 24.04).
				ServiceName: "ipsec",
				ServerID:    publicHost,
				Pool:        pool,
				DNS:         []string{dns},
				SSH:         ssh,
				Store:       ikev2.StoreAdapter{S: m.store},
				Enc:         m.enc,
			}))
		case "xray":
			providers = append(providers, xray.New(xray.Options{
				Instance:    scope(inst.LocalName),
				ConfigPath:  "/usr/local/etc/xray/config.json",
				ServiceName: "xray",
				PublicHost:  publicHost,
				SSH:         ssh,
				Store:       xray.StoreAdapter{S: m.store},
				Enc:         m.enc,
			}))
		default:
			slog.Warn("servers.Manager: unknown instance type, skipping", "server", srv.ID, "type", inst.Type, "name", inst.LocalName)
		}
	}

	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.Name()
	}
	return providers, names, nil
}
