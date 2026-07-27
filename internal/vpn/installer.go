package vpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"protean/internal/hostboot"
)

// InstallerPath is where setup-host.sh places the root-owned installer that
// the panel is allowed to run via sudo. It's a fixed path so the sudoers
// rule can target exactly it.
const InstallerPath = "/usr/local/lib/protean/protean-installer.sh"

// installerRunner is the SSH surface the installer wrapper needs (satisfied
// by *sshexec.Client).
type installerRunner interface {
	Run(ctx context.Context, cmd string) (string, error)
}

// HostInfo is the parsed output of the installer's `detect` verb.
type HostInfo struct {
	OSFamily         string                  `json:"os_family"`
	PrettyName       string                  `json:"pretty_name"`
	PkgManager       string                  `json:"pkg_manager"`
	Systemd          bool                    `json:"systemd"`
	SELinuxEnforcing bool                    `json:"selinux_enforcing"`
	Supported        bool                    `json:"supported"`
	Providers        map[string]ProviderInfo `json:"providers"`
	Error            string                  `json:"error"`
}

type ProviderInfo struct {
	Installed   bool `json:"installed"`
	Installable bool `json:"installable"`
	// ServiceActive/ConfigExists are best-effort signals (checked against the
	// panel's own conventional service unit/config path) that the host
	// already looks provisioned for this provider -- surfaced so "Set up"
	// can warn before silently replacing an existing CA/config. A foreign
	// install using a non-standard location won't be caught; only wired up
	// for cert-based providers (openvpn/ikev2) today, always false otherwise.
	ServiceActive bool `json:"service_active"`
	ConfigExists  bool `json:"config_exists"`
}

// Installer drives the on-host installer script over SSH.
type Installer struct {
	ssh installerRunner
}

func NewInstaller(ssh installerRunner) *Installer {
	return &Installer{ssh: ssh}
}

// run executes one installer.sh verb, self-healing the mismatch that
// happens when the panel gains a new verb (e.g. subnet-nat) but an
// already-provisioned host's on-disk copy of the script -- written ONCE by
// setup-host.sh/the bootstrap flow, never auto-updated since -- doesn't
// have it yet. The script's own fallback case prints "usage: <path>
// {...}" and exits 2 for any verb it doesn't recognize; on exactly that
// signal, push a fresh copy of the embedded script (protean-installer.sh
// and hostboot's embedded copy are kept in sync, see hostboot.go) and
// retry the original command once. Any other failure (a real error from
// a verb the script DOES recognize) is returned as-is, no retry.
func (i *Installer) run(ctx context.Context, args string) (string, error) {
	cmd := "sudo " + InstallerPath + " " + args
	out, err := i.ssh.Run(ctx, cmd)
	if err != nil && strings.Contains(err.Error(), "usage: "+InstallerPath) {
		if refreshErr := i.refreshScript(ctx); refreshErr == nil {
			out, err = i.ssh.Run(ctx, cmd)
		}
	}
	return out, err
}

func (i *Installer) refreshScript(ctx context.Context) error {
	encoded := base64.StdEncoding.EncodeToString(hostboot.InstallerScript())
	_, err := i.ssh.Run(ctx, "echo "+encoded+" | base64 -d | sudo tee "+InstallerPath+" >/dev/null && sudo chmod 750 "+InstallerPath)
	return err
}

var validProvider = regexp.MustCompile(`^(wireguard|amneziawg|openvpn|ikev2|xray)$`)

// Detect returns the host's OS/provider state.
func (i *Installer) Detect(ctx context.Context) (HostInfo, error) {
	out, err := i.run(ctx, "detect")
	if err != nil {
		return HostInfo{}, fmt.Errorf("run detect: %w", err)
	}
	return ParseHostInfo(out)
}

// ParseHostInfo parses the installer's detect JSON. Split out for testing.
func ParseHostInfo(jsonOut string) (HostInfo, error) {
	var info HostInfo
	if err := json.Unmarshal([]byte(jsonOut), &info); err != nil {
		return HostInfo{}, fmt.Errorf("parse detect json: %w", err)
	}
	if info.Error != "" {
		return info, fmt.Errorf("installer detect error: %s", info.Error)
	}
	return info, nil
}

// Install runs the installer for one provider and returns its combined
// output. provider is validated against the same whitelist the script
// enforces, as defense in depth.
func (i *Installer) Install(ctx context.Context, provider string) (string, error) {
	if !validProvider.MatchString(provider) {
		return "", fmt.Errorf("invalid provider %q", provider)
	}
	out, err := i.run(ctx, "install "+provider)
	if err != nil {
		return out, fmt.Errorf("install %s: %w", provider, err)
	}
	return out, nil
}

var (
	validAction = regexp.MustCompile(`^(start|stop|restart|enable|disable)$`)
	validUnit   = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)
)

// Service controls a systemd unit (start|stop|restart|enable|disable) via the
// installer. Used to stop/disable VPN daemons that aren't in use.
func (i *Installer) Service(ctx context.Context, action, unit string) (string, error) {
	if !validAction.MatchString(action) {
		return "", fmt.Errorf("invalid action %q", action)
	}
	if !validUnit.MatchString(unit) {
		return "", fmt.Errorf("invalid unit %q", unit)
	}
	out, err := i.run(ctx, "service "+action+" "+unit)
	if err != nil {
		return out, fmt.Errorf("service %s %s: %w", action, unit, err)
	}
	return out, nil
}

var validCIDR = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$`)

// Forward manages a mesh FORWARD-accept rule for a subnet (add|del), used to
// bring cert-based providers into the cross-provider mesh (their interface
// name isn't fixed, so rules key on the subnet). No NAT.
func (i *Installer) Forward(ctx context.Context, action, cidr string) error {
	if action != "add" && action != "del" {
		return fmt.Errorf("invalid forward action %q", action)
	}
	if !validCIDR.MatchString(cidr) {
		return fmt.Errorf("invalid cidr %q", cidr)
	}
	_, err := i.run(ctx, "forward "+action+" "+cidr)
	return err
}

// SubnetNAT manages a MASQUERADE rule (add|del) for one catalogued site
// subnet's outbound-to-mesh traffic, excluding the host's own WAN interface
// (auto-detected on the host) so masquerade mode never also grants that
// subnet internet egress -- that stays internet_egress's separate job,
// which only ever NATs an instance's own tunnel CIDR. Subnet-keyed rather
// than interface-keyed, mirroring Forward: the site subnet lives behind a
// peer, not behind a wg-quick interface the panel could inject
// PostUp/PostDown lines into.
func (i *Installer) SubnetNAT(ctx context.Context, action, cidr string) error {
	if action != "add" && action != "del" {
		return fmt.Errorf("invalid subnet-nat action %q", action)
	}
	if !validCIDR.MatchString(cidr) {
		return fmt.Errorf("invalid cidr %q", cidr)
	}
	_, err := i.run(ctx, "subnet-nat "+action+" "+cidr)
	return err
}

// EnsureIPForward turns on net.ipv4.ip_forward on the host if it isn't
// already (idempotent). Called whenever mesh/egress routing is turned on --
// setup-host.sh's interactive bootstrap only ever offers this once, so a
// host that later loses the sysctl (reboot without /etc/sysctl.d surviving,
// or a manual override) would otherwise silently stop routing between
// sites/egress until someone happened to notice.
func (i *Installer) EnsureIPForward(ctx context.Context) error {
	_, err := i.run(ctx, "ensure-ip-forward")
	return err
}

// ServiceStatus returns "active"/"inactive"/"unknown" for a unit.
func (i *Installer) ServiceStatus(ctx context.Context, unit string) (string, error) {
	if !validUnit.MatchString(unit) {
		return "", fmt.Errorf("invalid unit %q", unit)
	}
	out, err := i.run(ctx, "status "+unit)
	if err != nil {
		return "unknown", nil
	}
	return strings.TrimSpace(out), nil
}

// UpdatesInfo summarizes a host's pending OS package updates (installer.sh's
// "updates-check" verb). Output is deliberately raw per-family listing text,
// not a structured per-package list -- apt/dnf/pacman/zypper each format
// this completely differently, and the raw text is still genuinely useful
// to an admin without needing four distinct parsers.
type UpdatesInfo struct {
	Count          int    `json:"count"`
	RebootRequired bool   `json:"reboot_required"`
	Output         string `json:"output"`
	Error          string `json:"error"`
}

// CheckUpdates queries pending OS package updates on the host. Read-only
// except for a package-index refresh (apt-get update / pacman -Sy / zypper
// refresh), matching each package manager's own idiom for "check".
func (i *Installer) CheckUpdates(ctx context.Context) (UpdatesInfo, error) {
	out, err := i.run(ctx, "updates-check")
	if err != nil {
		return UpdatesInfo{}, fmt.Errorf("updates-check: %w", err)
	}
	var info UpdatesInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return UpdatesInfo{}, fmt.Errorf("parse updates-check output: %w", err)
	}
	if info.Error != "" {
		return info, fmt.Errorf("installer updates-check error: %s", info.Error)
	}
	return info, nil
}

// ServiceLogs returns the last `lines` lines of a unit's journal, so an
// admin can check what happened without opening an SSH session. lines is
// clamped to a sane range -- this only ever backs an admin-facing "View
// logs" button, not a general log-export feature.
func (i *Installer) ServiceLogs(ctx context.Context, unit string, lines int) (string, error) {
	if !validUnit.MatchString(unit) {
		return "", fmt.Errorf("invalid unit %q", unit)
	}
	if lines <= 0 || lines > 2000 {
		lines = 200
	}
	out, err := i.run(ctx, "logs "+unit+" "+strconv.Itoa(lines))
	if err != nil {
		return "", fmt.Errorf("logs %s: %w", unit, err)
	}
	return out, nil
}
