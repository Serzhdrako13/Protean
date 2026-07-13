package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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
}

// Installer drives the on-host installer script over SSH.
type Installer struct {
	ssh installerRunner
}

func NewInstaller(ssh installerRunner) *Installer {
	return &Installer{ssh: ssh}
}

var validProvider = regexp.MustCompile(`^(wireguard|amneziawg|openvpn|ikev2|xray)$`)

// Detect returns the host's OS/provider state.
func (i *Installer) Detect(ctx context.Context) (HostInfo, error) {
	out, err := i.ssh.Run(ctx, "sudo "+InstallerPath+" detect")
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
	out, err := i.ssh.Run(ctx, "sudo "+InstallerPath+" install "+provider)
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
	out, err := i.ssh.Run(ctx, "sudo "+InstallerPath+" service "+action+" "+unit)
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
	_, err := i.ssh.Run(ctx, "sudo "+InstallerPath+" forward "+action+" "+cidr)
	return err
}

// ServiceStatus returns "active"/"inactive"/"unknown" for a unit.
func (i *Installer) ServiceStatus(ctx context.Context, unit string) (string, error) {
	if !validUnit.MatchString(unit) {
		return "", fmt.Errorf("invalid unit %q", unit)
	}
	out, err := i.ssh.Run(ctx, "sudo "+InstallerPath+" status "+unit)
	if err != nil {
		return "unknown", nil
	}
	return strings.TrimSpace(out), nil
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
	out, err := i.ssh.Run(ctx, "sudo "+InstallerPath+" logs "+unit+" "+strconv.Itoa(lines))
	if err != nil {
		return "", fmt.Errorf("logs %s: %w", unit, err)
	}
	return out, nil
}
