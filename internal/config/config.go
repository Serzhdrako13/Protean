// Package config loads panel configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// splitCSV parses a comma-separated list into trimmed, non-empty entries.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type Config struct {
	ListenAddr string

	DatabaseURL string

	SSHHost    string
	SSHPort    int
	SSHUser    string
	SSHKeyPath string
	// SSHHostKey pins the host's public key (authorized_keys line format).
	// SSHKnownHostsPath is an alternative OpenSSH known_hosts file. If both
	// are empty the client trusts the key on first use and logs it.
	SSHHostKey        string
	SSHKnownHostsPath string
	// SSHCmdTimeout bounds a single remote command (backstops a stuck host).
	SSHCmdTimeout time.Duration
	// TrustProxy: when true, trust the X-Forwarded-For header for the client
	// IP (rate-limit/audit). Enable only behind a trusted reverse proxy.
	TrustProxy bool
	// CookieInsecure drops the Secure flag on cookies for plain-HTTP access.
	CookieInsecure bool

	SessionSecret string

	AdminUsername string
	AdminPassword string

	// EmergencyAdminUsername/Password: a break-glass local admin that stays
	// usable via password even while "Internal" login is toggled off in
	// the DB (internal_auth_settings) -- e.g. after switching fully to
	// LDAP/OIDC and then losing access to it. Unlike AdminUsername/
	// AdminPassword (only seed if the users table is empty), this account
	// is force-upserted on every startup while both vars are set, and
	// closes again the moment they're unset. See internal/auth/manager.go.
	EmergencyAdminUsername string
	EmergencyAdminPassword string

	// SecretKeyHex is a 32-byte AES-256 key (hex-encoded, 64 chars) used to
	// encrypt client private keys at rest.
	SecretKeyHex string

	// WireGuardInterfaces / AmneziaWGInterfaces are the interface names to
	// manage; one provider instance is registered per entry (multi-instance,
	// e.g. wg0,wg1 for multisite). Instance id == interface name; conf path
	// is derived as /etc/wireguard/<iface>.conf (and the AmneziaWG equivalent).
	WireGuardInterfaces []string
	AmneziaWGInterfaces []string

	// OpenVPN instance settings.
	OpenVPNInstance   string
	OpenVPNListenPort int
	OpenVPNServerNet  string
	OpenVPNServerMask string
	OpenVPNProto      string

	// IKEv2 settings.
	IKEv2Pool string
	IKEv2DNS  string

	// PublicHost is the VPS's public IP/hostname, used as the Endpoint in
	// generated client configs.
	PublicHost string

	// MetricsToken guards the /metrics endpoint (Bearer token). Empty
	// disables /metrics entirely.
	MetricsToken string

	// TrafficSampleInterval is how often per-provider rx/tx counters are
	// snapshotted for the traffic history chart. 0 disables sampling.
	TrafficSampleInterval time.Duration
	// TrafficRetention bounds how long samples are kept (disk-space knob for
	// small hosts); older rows are pruned hourly.
	TrafficRetention time.Duration

	// ConnectionHistoryRetention bounds how long connect/disconnect events
	// are kept (same disk-space trade-off as TrafficRetention); older rows
	// are pruned hourly. 0 keeps events forever.
	ConnectionHistoryRetention time.Duration

	// VPNSetupContentDir holds the self-service portal's "how to connect"
	// instructions as plain <lang>.json files -- a Docker volume mount by
	// convention, so an admin can edit app names/links/steps as software
	// changes without rebuilding the panel (see internal/vpnsetup).
	VPNSetupContentDir string

	// XrayModulesDir holds admin-authored Xray strategy modules (JSON files
	// describing a new transport/camouflage combo) -- a Docker volume mount
	// by convention, so a new DPI-evasion countermeasure can be dropped in
	// without a rebuild or restart (see internal/vpn/xray/filemodule.go).
	XrayModulesDir string

	// Console* tune the web SSH console (internal/console): how long an
	// idle session stays open, the hard cap on any session's total
	// duration, and how many concurrent sessions one admin (or the panel
	// overall) may hold at once.
	ConsoleIdleTimeout time.Duration
	ConsoleMaxSession  time.Duration
	ConsoleMaxPerUser  int
	ConsoleMaxTotal    int
	// ConsoleAllowedOrigins additionally authorizes WS upgrade Origins
	// beyond the request's own Host (always allowed) -- needed when a
	// reverse proxy fronts the panel under a different browser-facing
	// origin than the Host header the panel process itself sees.
	ConsoleAllowedOrigins []string
}

func Load() (Config, error) {
	c := Config{
		ListenAddr:        getEnv("LISTEN_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		SSHHost:           os.Getenv("SSH_HOST"),
		SSHUser:           os.Getenv("SSH_USER"),
		SSHKeyPath:        os.Getenv("SSH_KEY_PATH"),
		SSHHostKey:        os.Getenv("SSH_HOST_KEY"),
		SSHKnownHostsPath: os.Getenv("SSH_KNOWN_HOSTS"),
		SessionSecret:     os.Getenv("SESSION_SECRET"),
		AdminUsername:     os.Getenv("ADMIN_USERNAME"),
		AdminPassword:     os.Getenv("ADMIN_PASSWORD"),

		EmergencyAdminUsername: os.Getenv("EMERGENCY_ADMIN_USERNAME"),
		EmergencyAdminPassword: os.Getenv("EMERGENCY_ADMIN_PASSWORD"),
		SecretKeyHex:           os.Getenv("SECRET_KEY"),
		PublicHost:             os.Getenv("PUBLIC_HOST"),
		MetricsToken:           os.Getenv("METRICS_TOKEN"),

		VPNSetupContentDir: getEnv("VPN_SETUP_CONTENT_DIR", "/data/vpn-setup"),
		XrayModulesDir:     getEnv("XRAY_MODULES_DIR", "/data/xray-modules"),
	}
	// WG_INTERFACES (comma list) drives multi-instance; falls back to the
	// legacy single WG_INTERFACE, then "wg0".
	c.WireGuardInterfaces = splitCSV(getEnv("WG_INTERFACES", getEnv("WG_INTERFACE", "wg0")))
	c.AmneziaWGInterfaces = splitCSV(getEnv("AWG_INTERFACES", getEnv("AWG_INTERFACE", "awg0")))

	c.OpenVPNInstance = getEnv("OVPN_INSTANCE", "server")
	c.OpenVPNServerNet = getEnv("OVPN_SERVER_NET", "10.8.0.0")
	c.OpenVPNServerMask = getEnv("OVPN_SERVER_MASK", "255.255.255.0")
	c.OpenVPNProto = getEnv("OVPN_PROTO", "udp")
	ovpnPort, err := strconv.Atoi(getEnv("OVPN_PORT", "1194"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid OVPN_PORT: %w", err)
	}
	c.OpenVPNListenPort = ovpnPort

	c.IKEv2Pool = getEnv("IKEV2_POOL", "10.9.0.0/24")
	c.IKEv2DNS = getEnv("IKEV2_DNS", "1.1.1.1")

	port, err := strconv.Atoi(getEnv("SSH_PORT", "22"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid SSH_PORT: %w", err)
	}
	c.SSHPort = port

	cmdTimeout, err := strconv.Atoi(getEnv("SSH_CMD_TIMEOUT", "30"))
	if err != nil || cmdTimeout <= 0 {
		return Config{}, fmt.Errorf("invalid SSH_CMD_TIMEOUT (want positive seconds): %v", err)
	}
	c.SSHCmdTimeout = time.Duration(cmdTimeout) * time.Second

	// Core secrets/DB are always required. SSH_* are optional now: servers are
	// managed in the DB/UI. If SSH_HOST is set, it seeds a "default" server on
	// first run (legacy single-server upgrade), so its companions are required
	// only in that case.
	var missing []string
	required := map[string]string{
		"DATABASE_URL":   c.DatabaseURL,
		"SESSION_SECRET": c.SessionSecret,
		"SECRET_KEY":     c.SecretKeyHex,
	}
	if c.SSHHost != "" {
		required["SSH_USER"] = c.SSHUser
		required["SSH_KEY_PATH"] = c.SSHKeyPath
		required["PUBLIC_HOST"] = c.PublicHost
	}
	for name, val := range required {
		if val == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variables: %v", missing)
	}

	if len(c.SecretKeyHex) != 64 {
		return Config{}, fmt.Errorf("SECRET_KEY must be a 64-char hex string (32 bytes)")
	}
	if len(c.SessionSecret) < 16 {
		return Config{}, fmt.Errorf("SESSION_SECRET must be at least 16 characters")
	}

	// Fail fast if the (legacy) SSH key file isn't readable, rather than
	// surfacing it later while seeding the default server.
	if c.SSHKeyPath != "" {
		if _, err := os.ReadFile(c.SSHKeyPath); err != nil {
			return Config{}, fmt.Errorf("SSH_KEY_PATH not readable: %w", err)
		}
	}

	// Validate CIDR/proto fields so a typo fails at boot, not at provision.
	if _, _, err := net.ParseCIDR(c.IKEv2Pool); err != nil {
		return Config{}, fmt.Errorf("invalid IKEV2_POOL %q: %w", c.IKEv2Pool, err)
	}
	if net.ParseIP(c.OpenVPNServerNet) == nil {
		return Config{}, fmt.Errorf("invalid OPENVPN_SERVER_NET %q (want an IPv4 network address)", c.OpenVPNServerNet)
	}
	if net.ParseIP(c.OpenVPNServerMask) == nil {
		return Config{}, fmt.Errorf("invalid OPENVPN_SERVER_MASK %q (want a dotted netmask)", c.OpenVPNServerMask)
	}
	if c.OpenVPNProto != "udp" && c.OpenVPNProto != "tcp" {
		return Config{}, fmt.Errorf("invalid OPENVPN_PROTO %q (want udp or tcp)", c.OpenVPNProto)
	}

	c.TrustProxy = getEnv("TRUST_PROXY", "") == "1"
	c.CookieInsecure = getEnv("COOKIE_INSECURE", "") == "1"

	sampleSec, err := strconv.Atoi(getEnv("TRAFFIC_SAMPLE_INTERVAL_SECONDS", "60"))
	if err != nil {
		return c, fmt.Errorf("TRAFFIC_SAMPLE_INTERVAL_SECONDS: %w", err)
	}
	c.TrafficSampleInterval = time.Duration(sampleSec) * time.Second
	retentionHours, err := strconv.Atoi(getEnv("TRAFFIC_RETENTION_HOURS", "72"))
	if err != nil {
		return c, fmt.Errorf("TRAFFIC_RETENTION_HOURS: %w", err)
	}
	c.TrafficRetention = time.Duration(retentionHours) * time.Hour

	connHistRetentionHours, err := strconv.Atoi(getEnv("CONNECTION_HISTORY_RETENTION_HOURS", "720"))
	if err != nil {
		return c, fmt.Errorf("CONNECTION_HISTORY_RETENTION_HOURS: %w", err)
	}
	c.ConnectionHistoryRetention = time.Duration(connHistRetentionHours) * time.Hour

	if c.SSHHostKey == "" && c.SSHKnownHostsPath == "" {
		slog.Warn("SSH host key not pinned (SSH_HOST_KEY / SSH_KNOWN_HOSTS empty); trusting on first use -- pin it for production")
	}

	consoleIdleSec, err := strconv.Atoi(getEnv("CONSOLE_IDLE_TIMEOUT_SECONDS", "900"))
	if err != nil {
		return c, fmt.Errorf("CONSOLE_IDLE_TIMEOUT_SECONDS: %w", err)
	}
	c.ConsoleIdleTimeout = time.Duration(consoleIdleSec) * time.Second
	consoleMaxSec, err := strconv.Atoi(getEnv("CONSOLE_MAX_SESSION_SECONDS", "28800"))
	if err != nil {
		return c, fmt.Errorf("CONSOLE_MAX_SESSION_SECONDS: %w", err)
	}
	c.ConsoleMaxSession = time.Duration(consoleMaxSec) * time.Second
	c.ConsoleMaxPerUser, err = strconv.Atoi(getEnv("CONSOLE_MAX_PER_USER", "5"))
	if err != nil {
		return c, fmt.Errorf("CONSOLE_MAX_PER_USER: %w", err)
	}
	c.ConsoleMaxTotal, err = strconv.Atoi(getEnv("CONSOLE_MAX_TOTAL", "20"))
	if err != nil {
		return c, fmt.Errorf("CONSOLE_MAX_TOTAL: %w", err)
	}
	c.ConsoleAllowedOrigins = splitCSV(getEnv("CONSOLE_ALLOWED_ORIGINS", ""))

	return c, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
