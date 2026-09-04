#!/usr/bin/env bash
# protean-installer.sh -- the ONLY privileged action surface the panel has on
# the host. It is installed root-owned (0755 root:root) by setup-host.sh and
# invoked by the panel over SSH as `sudo /usr/local/lib/protean/protean-installer.sh <verb> ...`.
#
# Because this script is not writable by the panel's SSH user and accepts only
# a fixed set of verbs with whitelisted arguments, granting the panel
# passwordless sudo to THIS PATH does not grant it arbitrary root -- only the
# predefined actions below.
#
# Verbs:
#   detect                 -> print a JSON summary of the host to stdout
#   install <provider>     -> install a VPN backend (wireguard|amneziawg|openvpn|ikev2)
#   status  <unit>         -> print "active"/"inactive"/"unknown" for a systemd unit
#   ensure-ip-forward      -> turn on net.ipv4.ip_forward if it isn't already (idempotent)
#   updates-check          -> print pending OS package updates as JSON (read-only)
#   updates-apply          -> apply pending OS package updates (streamed to stdout)
#   firewall-baseline      -> print host listening-port/backend scan as JSON (read-only)
#   firewall-validate      -> dry-run validate a ruleset (read from stdin), no host changes
#   firewall-apply <window_secs> <ssh_port> <critical_ports_csv>
#                          -> apply an INPUT ruleset (read from stdin) with an armed rollback
#   firewall-confirm       -> persist the pending ruleset, cancel the rollback timer
#   firewall-rollback      -> restore the pre-apply snapshot (no-op if already confirmed)
#   firewall-status        -> print pending/confirmed firewall state as JSON (read-only)
#   firewall-boot-restore  -> restore the last-confirmed ruleset (systemd unit ExecStart)
#
# Keep this script dependency-free (POSIX-ish bash) and side-effect-free
# except for the explicit install actions.
set -uo pipefail

# --------------------------------------------------------------- OS detection

OS_FAMILY=""     # debian | rpm | arch | suse | altlinux
PKG_MANAGER=""   # apt | dnf | yum | pacman | zypper | apt-rpm
PRETTY_NAME=""
HAS_SYSTEMD=0
SELINUX_ENFORCING=0

detect_os() {
	[ -r /etc/os-release ] || return 1
	# shellcheck disable=SC1091
	. /etc/os-release
	PRETTY_NAME="${PRETTY_NAME:-${NAME:-unknown}}"

	case " ${ID:-} ${ID_LIKE:-} " in
		*" suse "*|*" opensuse "*|*" sles "*) OS_FAMILY="suse" ;;
		*" arch "*|*" archlinux "*)           OS_FAMILY="arch" ;;
		*" debian "*|*" ubuntu "*)            OS_FAMILY="debian" ;;
		*" rhel "*|*" fedora "*|*" centos "*) OS_FAMILY="rpm" ;;
		*" altlinux "*)                       OS_FAMILY="altlinux" ;;
		*)
			case "${ID:-}" in
				opensuse*|sles|suse) OS_FAMILY="suse" ;;
				arch|endeavouros|manjaro|garuda|arcolinux|cachyos|artix) OS_FAMILY="arch" ;;
				debian|ubuntu|linuxmint|pop|kali|raspbian|elementary|zorin|mx|deepin) OS_FAMILY="debian" ;;
				fedora|rhel|centos|rocky|almalinux|ol|amzn|mageia) OS_FAMILY="rpm" ;;
				altlinux) OS_FAMILY="altlinux" ;;
			esac
			;;
	esac

	# apt-rpm, not "apt": ALT's apt-get wraps rpm, not dpkg -- syntax matches
	# Debian's apt-get exactly, but the package SET doesn't (no "wireguard"
	# metapackage, only "wireguard-tools"; strongswan-swanctl isn't a
	# separate package, same single-package shape as RHEL/Arch/SUSE) --
	# confirmed live against alt:p10. Giving it its own PKG_MANAGER value
	# routes it through those distros' fallback branches instead of
	# Debian's, without changing any of that existing logic.
	if   command -v apt-get >/dev/null 2>&1 && [ "$OS_FAMILY" = "debian" ];   then PKG_MANAGER="apt"
	elif command -v apt-get >/dev/null 2>&1 && [ "$OS_FAMILY" = "altlinux" ]; then PKG_MANAGER="apt-rpm"
	elif command -v dnf     >/dev/null 2>&1 && [ "$OS_FAMILY" = "rpm" ];    then PKG_MANAGER="dnf"
	elif command -v yum     >/dev/null 2>&1 && [ "$OS_FAMILY" = "rpm" ];    then PKG_MANAGER="yum"
	elif command -v pacman  >/dev/null 2>&1 && [ "$OS_FAMILY" = "arch" ];   then PKG_MANAGER="pacman"
	elif command -v zypper  >/dev/null 2>&1 && [ "$OS_FAMILY" = "suse" ];   then PKG_MANAGER="zypper"
	fi

	[ -d /run/systemd/system ] && HAS_SYSTEMD=1
	if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
		SELINUX_ENFORCING=1
	fi
	return 0
}

have() { command -v "$1" >/dev/null 2>&1; }

provider_installed() {
	case "$1" in
		wireguard) have wg && have wg-quick ;;
		amneziawg) have awg && have awg-quick ;;
		openvpn)   have openvpn ;;
		ikev2)     have ipsec || have swanctl ;;
		xray)      have xray ;;
		*)         return 1 ;;
	esac
}

# provider_installable: whether install is even attemptable on this host.
# Everything needs a known package manager and systemd; AmneziaWG additionally
# has no clean path on some families.
provider_installable() {
	local p="$1"
	[ -n "$PKG_MANAGER" ] || return 1
	[ "$HAS_SYSTEMD" -eq 1 ] || return 1
	case "$p" in
		amneziawg)
			case "$OS_FAMILY" in
				debian|rpm) return 0 ;;                 # PPA/DEB822 or COPR
				arch) have yay || have paru ;;          # needs an AUR helper
				suse|altlinux) return 1 ;;              # no known package
			esac
			;;
		wireguard|openvpn|ikev2) return 0 ;;
		xray) return 0 ;;   # installed via the official get-xray script
		*) return 1 ;;
	esac
}

# --------------------------------------------------------------------- detect

json_bool() { if [ "$1" -eq 1 ] 2>/dev/null || [ "$1" = "true" ]; then printf 'true'; else printf 'false'; fi; }

# json_str <text>: JSON-quotes text for embedding as a string value (quotes
# included in the output). Good enough for printable command output --
# not a general-purpose JSON escaper (control characters other than
# newline/tab aren't handled), which is all this script's own callers
# ever feed it.
json_str() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\t'/\\t}"
	s="${s//$'\r'/}"
	printf '"%s"' "$s"
}

# provider_service_active/provider_config_exists: best-effort check for
# whether this host ALREADY looks provisioned by the panel's own conventional
# defaults (openvpn-server@server unit + /etc/openvpn/server/server.conf,
# ipsec unit + any /etc/swanctl/conf.d/*.conf) -- used to warn before "Set up"
# would overwrite an existing CA/config. Only meaningful for cert-based
# providers (wg-family's "Set up" doesn't destroy anything, it's just a
# config write); other providers always report false here.
provider_service_active() {
	command -v systemctl >/dev/null 2>&1 || return 1
	case "$1" in
		openvpn) unit_active "openvpn-server@server" ;;
		ikev2)   unit_active ipsec ;;
		*)       return 1 ;;
	esac
}

# unit_active <unit>: true if active, quiet -- same exit-code convention as
# `systemctl is-active --quiet`, but via `show -p ActiveState` instead.
# Confirmed live that is-active on a manually-aliased unit name (ipsec ->
# strongswan, openvpn-server@server -> openvpn@server on openSUSE, any
# Alias= target) can misreport "inactive" on systemd 232 (Astra Linux CE
# 2.12's bundled version) after any daemon-reload, even while the unit is
# genuinely running -- show's own ActiveState always resolves correctly
# regardless, on every systemd version tested.
unit_active() {
	[ "$(systemctl show "$1" -p ActiveState --value 2>/dev/null)" = "active" ]
}

provider_config_exists() {
	case "$1" in
		openvpn) [ -s /etc/openvpn/server/server.conf ] ;;
		ikev2)   ls /etc/swanctl/conf.d/*.conf >/dev/null 2>&1 ;;
		*)       return 1 ;;
	esac
}

provider_json() {
	local p="$1" inst=false able=false active=false cfg=false
	provider_installed "$p" && inst=true
	provider_installable "$p" && able=true
	provider_service_active "$p" && active=true
	provider_config_exists "$p" && cfg=true
	printf '"%s":{"installed":%s,"installable":%s,"service_active":%s,"config_exists":%s}' \
		"$p" "$inst" "$able" "$active" "$cfg"
}

cmd_detect() {
	detect_os || { echo '{"error":"cannot read /etc/os-release"}'; return 1; }
	local supported=0
	[ -n "$PKG_MANAGER" ] && [ "$HAS_SYSTEMD" -eq 1 ] && supported=1
	# Strip any double quotes from PRETTY_NAME for safe JSON embedding.
	local pretty="${PRETTY_NAME//\"/}"

	printf '{'
	printf '"os_family":"%s",' "$OS_FAMILY"
	printf '"pretty_name":"%s",' "$pretty"
	printf '"pkg_manager":"%s",' "$PKG_MANAGER"
	printf '"systemd":%s,' "$(json_bool "$HAS_SYSTEMD")"
	printf '"selinux_enforcing":%s,' "$(json_bool "$SELINUX_ENFORCING")"
	printf '"supported":%s,' "$(json_bool "$supported")"
	printf '"providers":{'
	printf '%s,' "$(provider_json wireguard)"
	printf '%s,' "$(provider_json amneziawg)"
	printf '%s,' "$(provider_json openvpn)"
	printf '%s,' "$(provider_json ikev2)"
	printf '%s'  "$(provider_json xray)"
	printf '}}'
	printf '\n'
}

# -------------------------------------------------------------- package helpers

pkg_install() {
	case "$PKG_MANAGER" in
		apt)    export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y "$@" ;;
		apt-rpm) export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y "$@" ;;
		dnf)    dnf install -y "$@" ;;
		yum)    yum install -y "$@" ;;
		pacman) pacman -Sy --noconfirm --needed "$@" ;;
		zypper)
			# Exit 107 (ZYPPER_EXIT_INF_RPM_SCRIPT_FAILED) means the
			# package installed fine but an rpm %post scriptlet
			# errored -- confirmed live: strongswan's scriptlet
			# calls systemctl, which fails with no live systemd
			# during a container build. Not a real install failure.
			zypper --non-interactive install -y "$@"
			local rc=$?
			[ "$rc" -eq 0 ] || [ "$rc" -eq 107 ]
			;;
		*)      echo "no supported package manager" >&2; return 1 ;;
	esac
}

aur_install() {
	local helper=""
	have yay && helper="yay"
	have paru && helper="paru"
	[ -n "$helper" ] || { echo "no AUR helper (yay/paru) found" >&2; return 1; }
	# AUR helpers refuse to run as root; drop to the invoking sudo user if any.
	local runas="${SUDO_USER:-}"
	if [ -n "$runas" ] && [ "$runas" != "root" ]; then
		sudo -u "$runas" "$helper" -S --noconfirm "$@"
	else
		echo "AUR install needs a non-root user (set SUDO_USER)" >&2
		return 1
	fi
}

selinux_note() {
	[ "$SELINUX_ENFORCING" -eq 1 ] || return 0
	echo "[i] SELinux is enforcing. WireGuard/AmneziaWG need no booleans, but if you"
	echo "    run services on non-default ports you may need: semanage port -a ..."
}

# ------------------------------------------------------------------- installers

install_wireguard() {
	case "$PKG_MANAGER" in
		apt)     pkg_install wireguard ;;
		# ALT splits wg-quick into its own package (wireguard-tools alone
		# only ships /usr/sbin/wg) -- confirmed live. Everything this
		# panel does server-side goes through the wg-quick@.service unit
		# (EnsureServer/ServiceName), so without this package the service
		# doesn't exist at all, not just a missing convenience CLI.
		apt-rpm) pkg_install wireguard-tools wireguard-tools-wg-quick ;;
		*)       pkg_install wireguard-tools ;;
	esac
	modprobe wireguard 2>/dev/null || echo "[!] could not load wireguard module (kernel may be <5.6 or need a dkms package)"
	selinux_note
	provider_installed wireguard
}

install_amneziawg() {
	case "$OS_FAMILY" in
		debian)
			# Ubuntu: PPA. Debian proper: the PPA won't resolve, so fall back to
			# the project's DEB822 repo instructions (left to the operator if the
			# PPA path fails).
			pkg_install software-properties-common ca-certificates || true
			if ! add-apt-repository -y ppa:amnezia/ppa 2>/dev/null; then
				echo "[!] Could not add ppa:amnezia/ppa (expected on non-Ubuntu Debian)." >&2
				echo "    Add the AmneziaWG DEB822 repo manually, then re-run install." >&2
				return 1
			fi
			# add-apt-repository only WRITES the source file -- it doesn't
			# check the PPA actually publishes a build for the host's
			# codename. Amnezia's PPA lags interim/very new Ubuntu releases;
			# confirmed live on 26.04 "resolute": add-apt-repository reports
			# success, then `apt-get update` fails with "does not have a
			# Release file". Pin the just-written entry to Ubuntu 24.04
			# "noble" instead -- Amnezia's PPA reliably tracks that LTS, and
			# its packages install fine on newer Ubuntu userspaces too.
			for f in /etc/apt/sources.list.d/amnezia-ubuntu-ppa-*.sources /etc/apt/sources.list.d/amnezia-ppa*.list; do
				[ -f "$f" ] && sed -i -E 's/^(Suites:).*/\1 noble/; s/ [a-z]+ main$/ noble main/' "$f"
			done
			if apt-get update -y && pkg_install amneziawg amneziawg-tools; then
				:
			else
				# Leaving the source file in place (broken, or now orphaned if
				# the noble pin also failed) breaks every SUBSEQUENT apt-get
				# update site-wide, not just this install -- confirmed live: a
				# failed amneziawg install broke the very next, unrelated
				# openvpn install with the same "no Release file" error until
				# this was cleaned up by hand. So on failure, always remove
				# what was just added before returning.
				echo "[x] AmneziaWG has no usable package for this distro/release (tried the noble pin) -- ppa:amnezia/ppa likely doesn't support it yet." >&2
				add-apt-repository -y --remove ppa:amnezia/ppa 2>/dev/null || true
				rm -f /etc/apt/sources.list.d/amnezia-ubuntu-ppa-*.sources /etc/apt/sources.list.d/amnezia-ppa*.list
				apt-get update -y >/dev/null 2>&1 || true
				return 1
			fi
			;;
		rpm)
			pkg_install dnf-plugins-core || true
			if dnf copr enable -y amneziavpn/amneziawg 2>/dev/null; then
				pkg_install amneziawg-tools amneziawg-dkms || pkg_install amneziawg-tools
			else
				echo "[!] Could not enable COPR amneziavpn/amneziawg." >&2
				return 1
			fi
			;;
		arch)
			aur_install amneziawg-tools amneziawg-dkms
			;;
		*)
			echo "[!] AmneziaWG has no supported install path on this distro." >&2
			return 1
			;;
	esac
	modprobe amneziawg 2>/dev/null || echo "[!] could not load amneziawg module yet (dkms build may need a reboot)"
	selinux_note
	provider_installed amneziawg
}

install_openvpn() {
	# RHEL-clones (not Fedora, which ships these directly in its own repos)
	# don't carry openvpn/easy-rsa in the base repos at all -- EPEL has to
	# be enabled first. Confirmed live: `dnf install openvpn easy-rsa`
	# fails outright on a stock Rocky Linux 9 without this.
	if [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
		if [ "${ID:-}" != "fedora" ]; then
			pkg_install epel-release || true
		fi
	fi
	case "$PKG_MANAGER" in
		apt|apt-rpm|dnf|yum|pacman) pkg_install openvpn easy-rsa ;;
		zypper)             pkg_install openvpn easy-rsa ;;
	esac
	ensure_openvpn_alias
	echo "[i] OpenVPN installed but not configured -- the panel does not manage it yet."
	provider_installed openvpn
}

# The panel's Go code (internal/vpn/openvpn, internal/servers/manager.go)
# hardcodes both the Debian/RHEL unit template name "openvpn-server@<name>"
# AND its path convention (config at /etc/openvpn/server/<name>.conf,
# i.e. WorkingDirectory=/etc/openvpn/server + a relative "%i.conf").
# openSUSE's openvpn package ships neither: its own "openvpn@<name>"
# template resolves to the flat path /etc/openvpn/<name>.conf instead --
# confirmed live on opensuse/leap:15.6 ("Error opening configuration
# file: server.conf", cwd /etc/openvpn/, not /etc/openvpn/server/). A
# plain alias symlink to that template would just move the same path
# mismatch one level down, so instead write a real unit using the
# Debian-style WorkingDirectory/ExecStart, reusing the same openvpn
# binary the distro already installed.
ensure_openvpn_alias() {
	[ -e /etc/systemd/system/openvpn-server@.service ] && return 0
	local native
	for native in /usr/lib/systemd/system/openvpn-server@.service /lib/systemd/system/openvpn-server@.service; do
		[ -e "$native" ] || continue
		# A native template exists, but that alone isn't enough: ALT's own
		# ships one that --chroots into /var/lib/openvpn and drops to a
		# dedicated user via CLI flags (not systemd User=) -- confirmed
		# live, this makes it reinterpret the panel's absolute
		# --crl-verify/--client-config-dir paths as relative to the
		# chroot, so they resolve to a path that doesn't exist there
		# ("/var/lib/openvpn//etc/openvpn/server/crl.pem: No such file or
		# directory") even though the real file is right where the panel
		# wrote it. Only trust the native template when it doesn't chroot.
		if ! grep -q -- '--chroot' "$native"; then
			return 0 # native template already uses the expected convention
		fi
		break
	done
	local bin
	bin="$(command -v openvpn || echo /usr/sbin/openvpn)"
	cat > /etc/systemd/system/openvpn-server@.service <<EOF
[Unit]
Description=OpenVPN service for %I
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
PrivateTmp=true
RuntimeDirectory=openvpn-server
WorkingDirectory=/etc/openvpn/server
ExecStart=$bin --status /run/openvpn-server/status-%i.log --status-version 2 --suppress-timestamps --config %i.conf
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload 2>/dev/null || true
	return 0
}

install_ikev2() {
	case "$OS_FAMILY" in
		# strongswan-swanctl is a SEPARATE package on Debian/Ubuntu (unlike
		# every other distro family, which bundles the swanctl CLI into the
		# base strongswan package) -- without it, `swanctl` doesn't exist at
		# all and every ikev2 provider operation (load-all, list-sas, ...)
		# fails. Matches setup-host.sh's own package list for this OS family.
		debian) pkg_install strongswan strongswan-swanctl strongswan-pki libcharon-extra-plugins || pkg_install strongswan strongswan-swanctl ;;
		*)      pkg_install strongswan ;;
	esac
	ensure_ipsec_alias
	# ALT's swanctl binary was built with a different --with-swanctldir
	# default (/etc/strongswan/swanctl, not the universal /etc/swanctl
	# every other family here uses) -- confirmed live: `swanctl --load-all`
	# ran without error but silently loaded nothing ("no files found" for
	# every subdirectory), since the panel always writes to /etc/swanctl
	# (ikev2.Options.SwanctlDir, hardcoded, same on every distro). Alias
	# the whole tree rather than duplicating every write.
	if [ "$OS_FAMILY" = "altlinux" ] && [ ! -L /etc/strongswan/swanctl ]; then
		# The package ships this as a real, non-empty directory (a
		# template swanctl.conf inside) -- confirmed live, not just an
		# absent path. rm -rf it before replacing with the alias symlink;
		# its content becomes unused once /etc/swanctl (what the panel
		# actually manages) is symlinked in its place. Unguarded rmdir
		# failing here under `set -e` previously killed the rest of this
		# script silently, including every install_* call after this one.
		rm -rf /etc/strongswan/swanctl
		ln -sf /etc/swanctl /etc/strongswan/swanctl
	fi
	provider_installed ikev2
}

# ensure_ipsec_alias: the rest of this panel assumes "ipsec" as the one
# portable strongSwan service name across every distro (see
# internal/vpn/ikev2/provider.go's ServiceName comment) -- true on Debian/
# Ubuntu, whose strongswan package declares an Alias=ipsec.service in its
# unit file (materialized into a real symlink only once something actually
# runs `systemctl enable`), but NOT on RHEL-family: confirmed live that
# Rocky Linux 9's strongswan package ships only strongswan.service /
# strongswan-starter.service with no "ipsec" alias at all, so
# `service enable ipsec` fails outright with "Unit file ipsec.service does
# not exist." File-based checks only (no `systemctl cat`/`show`/
# `daemon-reload`) -- this needs to work when called from a Docker image
# build too, where systemd isn't actually running as PID 1 yet to answer
# live queries (confirmed live: those all fail with "Failed to connect to
# bus" at build time, even though the plain enable/symlink operations
# below don't need a live daemon at all).
ensure_ipsec_alias() {
	[ -e /etc/systemd/system/ipsec.service ] && return 0
	local dir name f
	for dir in /usr/lib/systemd/system /lib/systemd/system; do
		for name in strongswan.service strongswan-starter.service; do
			f="$dir/$name"
			[ -f "$f" ] || continue
			if grep -q '^Alias=ipsec\.service' "$f" 2>/dev/null; then
				return 0 # native alias declared; `systemctl enable` materializes it at runtime
			fi
			ln -sf "$f" /etc/systemd/system/ipsec.service
			return 0
		done
	done
	echo "[!] no strongswan systemd unit found to alias as ipsec.service" >&2
	return 1
}

install_xray() {
	# Official installer (systemd service + /usr/local/bin/xray). Needs curl.
	have curl || pkg_install curl
	# openSUSE/SLE don't ship a "nobody" user in the base image (every
	# other family here does) -- the installer's own check_install_user
	# step hard-requires one and exits before doing anything else.
	# Confirmed live: fresh opensuse/leap:15.6 has no "nobody" account.
	if [ "$OS_FAMILY" = "suse" ] && ! id nobody >/dev/null 2>&1; then
		pkg_install system-user-nobody || true
	fi
	if ! bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; then
		# The official installer refuses outright on package managers/OSes
		# it doesn't recognize ("error: The script does not support the
		# package manager in this operating system") -- confirmed live on
		# ALT Linux. Fall back to fetching the release binary directly
		# (same technique as test/e2elab/loadtest/client.Dockerfile) and
		# writing the same unit shape the installer itself would have,
		# rather than depending on it recognizing every distro here.
		echo "[i] official Xray installer doesn't support this OS; installing the release binary directly" >&2
		curl -fsSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
		mkdir -p /usr/local/bin /usr/local/etc/xray
		unzip -o /tmp/xray.zip -d /usr/local/bin xray
		chmod +x /usr/local/bin/xray
		rm -f /tmp/xray.zip
		cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
RuntimeDirectory=xray
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF
	fi
	# Upstream unit runs as User=nobody, but /usr/local/etc/xray is locked
	# to 750 <service account> (config holds plaintext client UUIDs/Reality
	# keys, so it's not world-readable like the other conf dirs) -- nobody
	# then can't even traverse the directory to read its own config file.
	# Confirmed live: xray.service fails every start with EACCES on
	# config.json, on every distro. Run as the actual service account
	# instead, which already owns that directory -- no new privilege
	# surface, no loosening to world-readable.
	#
	# The account name was hardcoded "protean" here until this fix, which
	# broke on a host bootstrapped with a custom service-account name
	# (sshexec.BootstrapHost's "Add server" flow lets an admin choose one).
	# $SUDO_USER is set by sudo to whoever actually invoked this script
	# (the panel always runs it via sudo -- see InstallerPath's own
	# doc comment), so it reflects the real account regardless of name;
	# validated against the same charset useradd itself accepts before
	# it's written into a systemd unit file.
	local xray_user="${SUDO_USER:-protean}"
	if [[ ! "$xray_user" =~ ^[a-z0-9_-]{1,32}$ ]]; then
		echo "[!] \$SUDO_USER='$xray_user' is not a plausible username, falling back to 'protean' for the xray unit" >&2
		xray_user="protean"
	fi
	mkdir -p /etc/systemd/system/xray.service.d
	cat > /etc/systemd/system/xray.service.d/10-protean-user.conf <<EOF
[Service]
User=${xray_user}
Group=${xray_user}
EOF
	systemctl daemon-reload 2>/dev/null || true
	provider_installed xray
}

cmd_install() {
	local provider="$1"
	detect_os || { echo "cannot detect OS" >&2; return 1; }
	if [ -z "$PKG_MANAGER" ]; then
		echo "unsupported: no known package manager (apt/dnf/pacman/zypper)" >&2
		return 1
	fi
	if [ "$HAS_SYSTEMD" -ne 1 ]; then
		echo "unsupported: this host does not use systemd; install VPNs manually" >&2
		return 1
	fi

	echo "[*] Installing $provider on $PRETTY_NAME ($PKG_MANAGER)..."
	case "$provider" in
		wireguard) install_wireguard ;;
		amneziawg) install_amneziawg ;;
		openvpn)   install_openvpn ;;
		ikev2)     install_ikev2 ;;
		xray)      install_xray ;;
		*) echo "unknown provider: $provider" >&2; return 1 ;;
	esac
	local rc=$?
	if [ $rc -eq 0 ]; then
		echo "[+] $provider installed."
		grant_provider_sudo
		fix_provider_dirs "$provider"
	else
		echo "[x] $provider install failed." >&2
	fi
	return $rc
}

# fix_provider_dirs <provider>: (re-)grants the panel's config directories
# for one provider, called after every successful cmd_install. Mirrors
# scripts/setup-host.sh's own setup_conf_permissions, but that one runs
# ONCE at initial bootstrap, gated on which providers were selected in
# THAT SAME interactive run -- installing a provider LATER from the
# panel (the flow this script's own bootstrap prompt recommends: "VPNs
# can also be installed later from the panel's Install page") never
# retroactively grants its directories, leaving the panel able to
# restart the resulting service (that grant, from grant_provider_sudo/
# setup-host.sh's systemctl entries, is unconditional) but never able to
# actually write its config. Same two-model detection as
# cmd_fix_conf_perms: group-based (setup-host.sh) if protean-conf
# exists, else owner-based (sshexec.BootstrapHost), using the SSH user
# this script is actually being invoked by ($SUDO_USER), not a
# hardcoded "protean".
fix_provider_dirs() {
	local provider="$1" owner="${SUDO_USER:-protean}"
	[[ "$owner" =~ ^[a-z0-9_-]{1,32}$ ]] || owner="protean"
	# traverseOnly: group needs to pass through, never write directly
	# (only relevant to the group model -- the owner model uses a single
	# 750 for everything, since the owner already has full rwx by
	# definition regardless of which dir it is).
	local traverseOnly=() dirs=()
	case "$provider" in
		openvpn) traverseOnly=(/etc/openvpn); dirs=(/etc/openvpn/server) ;;
		ikev2)   dirs=(/etc/swanctl /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private /etc/swanctl/conf.d /etc/swanctl/x509crl) ;;
		xray)    dirs=(/usr/local/etc/xray) ;;
		*)       return 0 ;; # wireguard/amneziawg: handled per-file by fix-conf-perms, not per-directory here
	esac
	local d
	if getent group protean-conf >/dev/null 2>&1; then
		for d in "${traverseOnly[@]}"; do
			[ -d "$d" ] || continue
			install -d -m 2750 -g protean-conf "$d"
		done
		for d in "${dirs[@]}"; do
			[ -d "$d" ] || continue
			install -d -m 2770 -g protean-conf "$d"
		done
		[ -d "${dirs[0]}" ] && chgrp -R protean-conf "${dirs[0]}" 2>/dev/null
	else
		id -u "$owner" >/dev/null 2>&1 || return 0
		for d in "${traverseOnly[@]}" "${dirs[@]}"; do
			[ -d "$d" ] || continue
			install -d -m 750 -o "$owner" "$d"
			chown -R "$owner":"$owner" "$d" 2>/dev/null || true
		done
	fi
}

# grant_provider_sudo: regenerates a SEPARATE sudoers fragment (never
# touches /etc/sudoers.d/protean, setup-host.sh's own file) covering
# wg/awg/swanctl -- the three binaries the panel calls directly over SSH
# with no protean-installer.sh verb equivalent (`wg set`/`wg show`,
# `awg set`/`awg show`, `swanctl --list-sas`/`--load-all`).
#
# setup-host.sh's one-time sudoers generation only grants these when that
# provider was ALREADY installed at bootstrap time -- but the script's own
# prompt says VPNs "can also be installed later from the panel's Install
# page" (cmd_install, right here). Installing wireguard/amneziawg/ikev2
# that way left the panel able to restart the resulting service (that
# grant IS unconditional) but never able to read its peer list or push a
# config, since the direct binary was never granted. Called after every
# successful install so it self-corrects regardless of install order,
# using `command -v` to grant whatever path this distro/package actually
# put the binary at -- not a guessed path, which would be wrong on
# non-Debian families (Arch/RPM, or a distro that ships an alternate
# prefix).
grant_provider_sudo() {
	local owner="${SUDO_USER:-protean}"
	[[ "$owner" =~ ^[a-z0-9_-]{1,32}$ ]] || owner="protean"
	local cmds=() p
	# wg/awg scoped to `show *`/`set *` -- the only shapes
	# internal/vpn/wgfamily ever runs -- not the bare binary. swanctl
	# scoped to the two EXACT commands internal/vpn/ikev2 ever runs
	# (neither takes variable arguments). A bare grant on any of these
	# would cover subcommands the panel never needs, no upside; see
	# scripts/setup-host.sh's own setup_sudoers for the same narrowing
	# and the wg-quick-specific reasoning (root shell via PostUp
	# injection) that motivated it.
	if p=$(command -v wg 2>/dev/null) && [ -n "$p" ]; then
		cmds+=("${p} show *" "${p} set *")
	fi
	if p=$(command -v awg 2>/dev/null) && [ -n "$p" ]; then
		cmds+=("${p} show *" "${p} set *")
	fi
	if p=$(command -v swanctl 2>/dev/null) && [ -n "$p" ]; then
		cmds+=("${p} --list-sas" "${p} --load-all")
	fi
	[ ${#cmds[@]} -gt 0 ] || return 0

	local f="/etc/sudoers.d/protean-provider-sudo"
	{
		echo "# Managed by protean-installer.sh's grant_provider_sudo -- regenerated"
		echo "# on every successful VPN install so this tracks what's actually"
		echo "# installed, not just what was present at scripts/setup-host.sh's"
		echo "# initial bootstrap. Do not edit by hand; it will be overwritten."
		printf 'Cmnd_Alias PROTEAN_PROVIDER_CMDS = %s\n' "$(IFS=,; echo "${cmds[*]}")"
		echo "${owner} ALL=(root) NOPASSWD: PROTEAN_PROVIDER_CMDS"
	} > "${f}.new"

	if visudo -cf "${f}.new" >/dev/null 2>&1; then
		mv "${f}.new" "$f"
		chmod 440 "$f"
		echo "[+] granted sudo for: ${cmds[*]}"
	else
		echo "[!] generated sudoers fragment failed validation, not installed" >&2
		rm -f "${f}.new"
	fi
}

cmd_status() {
	local unit="$1"
	if ! command -v systemctl >/dev/null 2>&1; then echo "unknown"; return 0; fi
	if unit_active "$unit"; then echo "active"; else echo "inactive"; fi
}

# cmd_logs <unit> <lines>: last N lines of a unit's journal, so an admin can
# check what happened from the panel without an SSH session.
cmd_logs() {
	local unit="$1" lines="$2"
	command -v journalctl >/dev/null 2>&1 || { echo "no journalctl" >&2; return 1; }
	journalctl -u "$unit" -n "$lines" --no-pager
}

# cmd_forward <add|del> <cidr>: manage a mesh FORWARD-accept rule for a subnet
# (used for cert-based providers whose interface name isn't fixed, so rules key
# on the subnet). No NAT -- site-to-site. Idempotent.
cmd_forward() {
	local action="$1" cidr="$2"
	command -v iptables >/dev/null 2>&1 || { echo "no iptables" >&2; return 1; }
	local c="protean-mesh"
	case "$action" in
		add)
			iptables -C FORWARD -s "$cidr" -j ACCEPT -m comment --comment "$c" 2>/dev/null || \
				iptables -A FORWARD -s "$cidr" -j ACCEPT -m comment --comment "$c"
			iptables -C FORWARD -d "$cidr" -j ACCEPT -m comment --comment "$c" 2>/dev/null || \
				iptables -A FORWARD -d "$cidr" -j ACCEPT -m comment --comment "$c"
			;;
		del)
			iptables -D FORWARD -s "$cidr" -j ACCEPT -m comment --comment "$c" 2>/dev/null || true
			iptables -D FORWARD -d "$cidr" -j ACCEPT -m comment --comment "$c" 2>/dev/null || true
			;;
		*) echo "invalid action" >&2; return 2 ;;
	esac
}

# cmd_subnet_nat <add|del> <cidr>: manage a MASQUERADE rule for one site
# subnet's outbound-to-mesh traffic, excluding this host's own default-route
# (WAN) interface so it never also grants that subnet unintended internet
# egress via the server (that stays the separate internet_egress feature's
# job, which NATs only an instance's own tunnel CIDR). Idempotent.
cmd_subnet_nat() {
	local action="$1" cidr="$2"
	command -v iptables >/dev/null 2>&1 || { echo "no iptables" >&2; return 1; }
	local wan
	wan="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
	local c="protean-subnet-nat"
	case "$action" in
		add)
			if [ -n "$wan" ]; then
				iptables -t nat -C POSTROUTING -s "$cidr" ! -o "$wan" -j MASQUERADE -m comment --comment "$c" 2>/dev/null || \
					iptables -t nat -A POSTROUTING -s "$cidr" ! -o "$wan" -j MASQUERADE -m comment --comment "$c"
			else
				iptables -t nat -C POSTROUTING -s "$cidr" -j MASQUERADE -m comment --comment "$c" 2>/dev/null || \
					iptables -t nat -A POSTROUTING -s "$cidr" -j MASQUERADE -m comment --comment "$c"
			fi
			;;
		del)
			iptables -t nat -D POSTROUTING -s "$cidr" ! -o "$wan" -j MASQUERADE -m comment --comment "$c" 2>/dev/null || true
			iptables -t nat -D POSTROUTING -s "$cidr" -j MASQUERADE -m comment --comment "$c" 2>/dev/null || true
			;;
		*) echo "invalid action" >&2; return 2 ;;
	esac
}

# cmd_peer_forward_rules <peer/32> [dest1,dest2,...]: replace one VPN
# peer's FORWARD-chain destination allowlist (full sync -- always deletes
# every existing rule tagged for this peer first, then reinserts fresh, so
# repeated calls with a different destination list never leave stale
# rules behind). An empty/absent destination list means "delete only" --
# the peer goes back to fully unrestricted (today's default: nothing in
# this script's own FORWARD-ACCEPT-everywhere baseline changes for it).
#
# Rules always go in at position 1 (never appended): wg-family's own
# blanket per-interface accept (PostUp `iptables -I FORWARD -i %i -j
# ACCEPT`) is ALSO inserted at the head of the chain every time that
# interface (re)starts, so this peer's block must be freshly re-inserted
# at the top on every sync, or a later interface bounce would push that
# blanket accept above us and shadow the restriction entirely.
#
# Insertion order matters: the DROP pair goes in FIRST, then the ACCEPT
# pairs on top of it (each `-I FORWARD 1` pushes the previous insert down
# one) -- so the final top-to-bottom order is this peer's ALLOWs, then
# this peer's DROPs, then everything that existed before (other peers'
# blocks, the wg-family/mesh blanket accepts). Bidirectional pairs
# (matching both `-s`/`-d`) follow cmd_forward's own existing convention
# above, rather than conntrack/ESTABLISHED state.
cmd_peer_forward_rules() {
	local peer="$1" destcsv="${2:-}"
	command -v iptables >/dev/null 2>&1 || { echo "no iptables" >&2; return 1; }
	local tag="protean-peer-fw:${peer%/*}"

	# Delete pass: remove every existing rule tagged for this peer,
	# regardless of how many there were last sync.
	#
	# Two real bugs found live 2026-09-04, both silent (this whole block
	# was a no-op since the feature's first day, never once actually
	# deleting anything -- every sync just piled fresh rules on top,
	# discovered only because a THIRD apply finally made the accumulation
	# visible as duplicate/stale entries):
	#  1. `iptables -S` quotes the comment value ('--comment
	#     "protean-peer-fw:1.2.3.4"'), but the old grep pattern searched
	#     for `--comment $tag` with no quotes -- never matched, so the
	#     delete loop's input was always empty.
	#  2. Even with a matching line found, `iptables -D FORWARD
	#     ${spec#-A FORWARD }` word-splits the quoted comment WITHOUT
	#     stripping the quote characters (unquoted parameter expansion
	#     doesn't re-parse shell quoting the way a real command line
	#     would) -- iptables then looked for a rule whose comment was
	#     literally `"protean-peer-fw:1.2.3.4"`, quote characters and
	#     all, which never exists, and silently failed
	#     ("Bad rule", swallowed by `|| true`). Fixed by feeding the
	#     stripped spec through eval, which re-parses it as a fresh shell
	#     command line -- correctly interpreting the quotes this time --
	#     rather than a bare unquoted expansion. Safe here specifically
	#     because the content being eval'd is iptables' OWN canonical
	#     rendering of a rule this exact script previously inserted from
	#     already-validated peer/destination values, not raw external
	#     input.
	local spec
	while IFS= read -r spec; do
		[ -n "$spec" ] || continue
		eval "iptables -D FORWARD ${spec#-A FORWARD }" 2>/dev/null || true
	done <<EOF
$(iptables -S FORWARD 2>/dev/null | grep -F -- "$tag")
EOF

	[ -n "$destcsv" ] || return 0

	iptables -I FORWARD 1 -d "$peer" -j DROP -m comment --comment "$tag"
	iptables -I FORWARD 1 -s "$peer" -j DROP -m comment --comment "$tag"

	local dest
	local IFS=','
	for dest in $destcsv; do
		[[ "$dest" =~ $VALID_CIDR ]] || { echo "invalid destination $dest" >&2; return 2; }
		iptables -I FORWARD 1 -d "$peer" -s "$dest" -j ACCEPT -m comment --comment "$tag"
		iptables -I FORWARD 1 -s "$peer" -d "$dest" -j ACCEPT -m comment --comment "$tag"
	done
}

# cmd_fix_conf_perms <path> [owner]: re-assert panel access to a wg-family
# conf file. WireGuard's own SaveConfig=true feature rewrites the file
# FROM SCRATCH (via `wg showconf > file`, run by wg-quick's own down/
# PostDown hook) on every interface stop -- root:root 0600, regardless of
# which of the two provisioning models originally granted access. Real
# incident: an admin's routine "enable mesh forwarding" click restarted
# the interface (EnableForwarding always does a full reload) and the
# panel lost read access to its own peer list minutes later. Called from
# wgfamily's restart() right after every successful service restart, so
# this self-heals on every occasion that would otherwise break it, not
# just the one observed. Path is whitelisted to wg-family's own conf
# directories -- this verb must never be usable to chgrp/chown/chmod an
# arbitrary file.
#
# Two provisioning models exist and this verb must handle both -- fixed
# live 2026-09-03 after the group-only version below hard-failed every
# restart on a host provisioned by the OTHER model:
#   - scripts/setup-host.sh: `chgrp protean-conf; chmod 660` -- the panel
#     user is a MEMBER of a shared group. Detected by the group existing.
#   - sshexec.BootstrapHost (the panel's own "Add server" flow): `chown
#     <service user>` -- no shared group is ever created. Falls back to
#     this when protean-conf doesn't exist, using the owner the Go side
#     passes (the actual SSH user it authenticates as, not a hardcoded
#     "protean" -- BootstrapHost's service account name is admin-chosen).
cmd_fix_conf_perms() {
	local path="$1" owner="${2:-protean}"
	[[ "$path" =~ ^/etc/(wireguard|amnezia/amneziawg)/[A-Za-z0-9_.-]+\.conf$ ]] || {
		echo "invalid conf path" >&2
		return 2
	}
	[[ "$owner" =~ ^[a-z0-9_-]{1,32}$ ]] || { echo "invalid owner" >&2; return 2; }
	[ -f "$path" ] || { echo "no such file: $path" >&2; return 1; }
	if getent group protean-conf >/dev/null 2>&1; then
		chgrp protean-conf "$path"
		chmod 660 "$path"
		# g+x alone is a no-op unless the DIRECTORY's group is also
		# protean-conf -- setup-host.sh historically only did the former
		# (see setup_conf_permissions), leaving the panel unable to even
		# traverse into /etc/wireguard on hosts it hadn't already fixed by
		# hand. Asserted here too so a stale host self-heals on first use.
		chgrp protean-conf "$(dirname "$path")"
		chmod 2750 "$(dirname "$path")"
	else
		id -u "$owner" >/dev/null 2>&1 || { echo "no such user: $owner" >&2; return 1; }
		chown "$owner" "$path"
		chmod 600 "$path"
	fi
}

# cmd_ensure_ip_forward: turn on net.ipv4.ip_forward if it isn't already, the
# same sysctl drop-in setup-host.sh's interactive bootstrap uses -- but
# idempotent and non-interactive, so the panel can re-check/re-apply it any
# time mesh/egress gets turned on (a host reboot without the sysctl.d file
# surviving, or ip_forward toggled off out-of-band, would otherwise silently
# break routing between sites until someone noticed).
cmd_ensure_ip_forward() {
	if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "1" ]; then
		echo "already enabled"
		return 0
	fi
	echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-protean.conf
	sysctl -q -p /etc/sysctl.d/99-protean.conf
	echo "enabled"
}

# cmd_updates_check: read-only report of pending OS package updates, as
# JSON: {"count":N,"reboot_required":bool,"output":"<raw per-family listing>"}.
# "output" is deliberately raw per-family text, not a structured per-package
# {name,old,new} list -- apt/dnf/pacman/zypper each format this completely
# differently, and the raw listing is still genuinely useful to an admin
# without needing five distinct parsers. reboot_required is only detected
# via the two well-established, documented signals (Debian's
# /var/run/reboot-required, RHEL's `needs-restarting -r`) -- left false on
# Arch/openSUSE rather than guessing at an unverified heuristic.
cmd_updates_check() {
	detect_os || { echo '{"error":"cannot detect OS"}'; return 1; }
	if [ -z "$PKG_MANAGER" ]; then
		echo '{"error":"no known package manager"}'
		return 1
	fi
	local count=0 output="" reboot=0
	case "$PKG_MANAGER" in
		apt|apt-rpm)
			apt-get update -qq >/dev/null 2>&1 || true
			output="$(apt list --upgradable 2>/dev/null | grep -v '^Listing' || true)"
			[ -e /var/run/reboot-required ] && reboot=1
			;;
		dnf|yum)
			local rc=0
			output="$("$PKG_MANAGER" check-update -q 2>/dev/null)" || rc=$?
			# check-update's own convention: exit 100 means updates ARE
			# available (not a failure); anything else non-zero is real.
			if [ "$rc" -ne 0 ] && [ "$rc" -ne 100 ]; then
				echo "{\"error\":\"$PKG_MANAGER check-update failed (exit $rc)\"}"
				return 1
			fi
			if command -v needs-restarting >/dev/null 2>&1; then
				needs-restarting -r >/dev/null 2>&1 || reboot=1
			fi
			;;
		pacman)
			# Refreshes the local package db for an accurate -Qu -- a real
			# (tolerated) side effect of an otherwise read-only check, same
			# trade-off pacman itself expects (`-Sy` alone, no `-u`, is its
			# own documented "just sync" idiom).
			pacman -Sy --noconfirm >/dev/null 2>&1 || true
			output="$(pacman -Qu 2>/dev/null || true)"
			;;
		zypper)
			zypper --non-interactive refresh -q >/dev/null 2>&1 || true
			output="$(zypper --non-interactive list-updates 2>/dev/null | grep '^v ' || true)"
			;;
		*)
			echo "{\"error\":\"updates-check not supported for $PKG_MANAGER\"}"
			return 1
			;;
	esac
	count="$(printf '%s\n' "$output" | grep -c . || true)"
	printf '{"count":%d,"reboot_required":%s,"output":%s}\n' \
		"$count" "$(json_bool "$reboot")" "$(json_str "$output")"
}

# cmd_updates_apply: actually apply pending OS package updates. Output
# streams to stdout/stderr as the package manager produces it -- the caller
# (internal/console's bridge, over a real PTY) is what makes this show up
# live in the panel's UI rather than only after the whole thing finishes.
cmd_updates_apply() {
	detect_os || { echo "cannot detect OS" >&2; return 1; }
	case "$PKG_MANAGER" in
		apt|apt-rpm)
			export DEBIAN_FRONTEND=noninteractive
			apt-get update -y && apt-get upgrade -y
			;;
		dnf) dnf upgrade -y ;;
		yum) yum upgrade -y ;;
		pacman) pacman -Syu --noconfirm ;;
		zypper)
			zypper --non-interactive update -y
			local rc=$?
			# 102/103 (ZYPPER_EXIT_INF_REBOOT_NEEDED / ..._RESTART_NEEDED)
			# are zypper's own documented "succeeded, but..." codes, not
			# failures -- same idiom as the 107 tolerance in pkg_install.
			[ "$rc" -eq 0 ] || [ "$rc" -eq 102 ] || [ "$rc" -eq 103 ]
			;;
		*)
			echo "unsupported package manager: $PKG_MANAGER" >&2
			return 1
			;;
	esac
}

# ------------------------------------------------------------- firewall
#
# INPUT-chain management with a real safety net: firewall-apply arms a
# host-side rollback timer BEFORE swapping in the new ruleset, so a
# ruleset that severs the very SSH session applying it still gets
# reverted -- the timer is a transient systemd unit (systemd is already a
# hard requirement everywhere this script runs, see HAS_SYSTEMD above),
# fully detached from this SSH session's process group by construction
# (PID 1 owns it), unlike a backgrounded/disowned shell job. Only
# firewall-confirm (called by the panel over a FRESH, non-pooled SSH
# connection -- proving new connections actually still work, not just
# that the one already-open stream survived via an ESTABLISHED accept)
# ever persists a change past that window. Comment namespace "protean-fw",
# disjoint from cmd_forward's "protean-mesh" and wg-quick's own
# PostUp/PostDown-embedded rules, so none of them collide.
FW_RUN_DIR="/run/protean-fw"
FW_ETC_DIR="/etc/protean-fw"
FW_ROLLBACK_UNIT="protean-fw-rollback"

# fw_conflicting_manager: true if ufw or firewalld is actively running.
# This feature refuses to fight them rather than trying to co-exist --
# iptables-save/restore wouldn't see rules those tools manage their own
# way, and two managers touching the same iptables state is a real path
# to an inconsistent ruleset. Same stance setup-host.sh's firewall_hints
# already takes (print hints, never seize raw control).
fw_conflicting_manager() {
	command -v systemctl >/dev/null 2>&1 || return 1
	systemctl is-active --quiet ufw 2>/dev/null && return 0
	systemctl is-active --quiet firewalld 2>/dev/null && return 0
	return 1
}

# fw_pending: true if a previous apply's rollback window is still open
# (unconfirmed, timer not yet fired). Shared by firewall-apply (refuses a
# second apply on top of an unconfirmed one -- superseding it would make
# "roll back" revert to an also-unconfirmed intermediate state instead of
# the last known-good one, which is worse than just asking the admin to
# confirm or roll back the pending change first) and firewall-status.
fw_pending() {
	[ -f "$FW_RUN_DIR/pending.rules" ] || return 1
	[ -f "$FW_RUN_DIR/committed" ] && return 1
	[ "$(systemctl show "${FW_ROLLBACK_UNIT}.timer" -p LoadState --value 2>/dev/null)" = "loaded" ]
}

# ensure_fw_boot_unit: (re)writes the boot-restore oneshot unit -- created
# lazily by firewall-confirm the first time a server actually confirms a
# change, rather than during initial host bootstrap, since this feature is
# opt-in per server. "$0" is this script's own invocation path -- always
# the fixed InstallerPath the panel sudo-invokes, never something to
# hardcode a second time here.
ensure_fw_boot_unit() {
	cat > /etc/systemd/system/protean-firewall.service <<EOF
[Unit]
Description=Protean firewall boot restore
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=$0 firewall-boot-restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
}

# cmd_firewall_baseline: read-only host scan for the panel's baseline
# computation -- what's actually listening, whether iptables is present,
# whether a conflicting manager is active. JSON on stdout, always exit 0
# (status lives in the payload -- sshexec.Client.Run discards stdout on a
# non-zero exit, so a real error here would otherwise vanish).
cmd_firewall_baseline() {
	local conflict=0 has_iptables=0
	fw_conflicting_manager && conflict=1
	command -v iptables >/dev/null 2>&1 && has_iptables=1
	local tcp udp
	tcp="$(ss -H -tln 2>/dev/null | awk '{print $4}' | sed -E 's/.*://' | sort -un | tr '\n' ',' | sed 's/,$//')"
	udp="$(ss -H -uln 2>/dev/null | awk '{print $4}' | sed -E 's/.*://' | sort -un | tr '\n' ',' | sed 's/,$//')"
	printf '{"has_iptables":%s,"conflicting_manager":%s,"listening_tcp":%s,"listening_udp":%s}\n' \
		"$(json_bool "$has_iptables")" "$(json_bool "$conflict")" "$(json_str "$tcp")" "$(json_str "$udp")"
}

# cmd_firewall_validate: dry-run only -- validates a ruleset (read from
# stdin, same heredoc technique as firewall-apply) via
# `iptables-restore --test`, touching nothing else on the host at all (no
# snapshot, no armed timer, no swap). Always exits 0; result is in the
# JSON payload.
cmd_firewall_validate() {
	if fw_conflicting_manager; then
		echo '{"valid":false,"error":"a conflicting firewall manager (ufw/firewalld) is active"}'
		return 0
	fi
	if ! command -v iptables-restore >/dev/null 2>&1; then
		echo '{"valid":false,"error":"iptables-restore not found"}'
		return 0
	fi
	local tmp test_err
	tmp="$(mktemp)"
	cat > "$tmp"
	if test_err="$(iptables-restore --test < "$tmp" 2>&1)"; then
		rm -f "$tmp"
		echo '{"valid":true}'
	else
		rm -f "$tmp"
		echo "{\"valid\":false,\"error\":$(json_str "$test_err")}"
	fi
}

# cmd_firewall_apply <window_secs> <ssh_port> <critical_ports_csv>: reads
# the desired ruleset from stdin (a heredoc on the invoking command line,
# same technique WriteFile already uses elsewhere -- never a shell-
# interpreted argv value). critical_ports_csv is "proto:port,proto:port,...".
cmd_firewall_apply() {
	local window="$1" ssh_port="$2" critical_csv="$3"
	if [ "$window" -lt 30 ] || [ "$window" -gt 3600 ]; then
		echo '{"error":"window out of range (30-3600)"}'
		return 1
	fi
	if fw_conflicting_manager; then
		echo '{"error":"a conflicting firewall manager (ufw/firewalld) is active; refusing"}'
		return 1
	fi
	if fw_pending; then
		echo '{"error":"a previous firewall change is still pending confirmation; confirm or roll it back first"}'
		return 1
	fi
	command -v iptables >/dev/null 2>&1 || { echo '{"error":"iptables not found"}'; return 1; }

	mkdir -p "$FW_RUN_DIR" "$FW_ETC_DIR"
	iptables-save > "$FW_RUN_DIR/snapshot.rules"
	cat > "$FW_RUN_DIR/pending.rules"
	rm -f "$FW_RUN_DIR/committed"

	local test_err
	if ! test_err="$(iptables-restore --test < "$FW_RUN_DIR/pending.rules" 2>&1)"; then
		echo "{\"error\":\"ruleset failed validation: $(json_str "$test_err")\"}"
		return 1
	fi

	# Arm the rollback BEFORE the swap: if the swap itself severs this
	# session, the timer is already ticking and will restore. Record the
	# arm time/window ourselves in plain files for firewall-status's
	# countdown -- confirmed live that systemd (252) pretty-prints
	# NextElapseUSecMonotonic as a human string ("2w 3d 9h ...") rather
	# than a raw number for an --on-active timer, and NextElapseUSecRealtime
	# stays empty for a monotonic timer entirely, so neither is a reliable
	# machine-parseable source of "seconds remaining" -- our own arithmetic
	# against a plain timestamp file sidesteps that entirely.
	date +%s > "$FW_RUN_DIR/armed_at"
	echo "$window" > "$FW_RUN_DIR/window_secs"
	if ! systemd-run --collect --unit="$FW_ROLLBACK_UNIT" --on-active="${window}s" \
			"$0" firewall-rollback >/dev/null 2>&1; then
		echo '{"error":"failed to arm rollback timer; aborting apply"}'
		return 1
	fi

	iptables-restore < "$FW_RUN_DIR/pending.rules"

	# Guard-insert at INPUT position 1 regardless of what the supplied
	# ruleset says -- a rendering bug on the panel side can never produce
	# an actual lockout. Inserted in this order so lo/established end up
	# evaluated first (each -I 1 pushes the previous guard down one slot).
	if [ -n "$critical_csv" ]; then
		local old_ifs="$IFS" entry proto port
		IFS=','
		for entry in $critical_csv; do
			proto="${entry%%:*}"
			port="${entry#*:}"
			iptables -I INPUT 1 -p "$proto" --dport "$port" -j ACCEPT -m comment --comment protean-fw-guard
		done
		IFS="$old_ifs"
	fi
	iptables -I INPUT 1 -p tcp --dport "$ssh_port" -j ACCEPT -m comment --comment protean-fw-guard
	iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment protean-fw-guard
	iptables -I INPUT 1 -i lo -j ACCEPT -m comment --comment protean-fw-guard

	printf '{"applied":true,"rollback_window_secs":%d}\n' "$window"
}

# cmd_firewall_confirm: persists the pending change past the rollback
# window. Race-safe against a timer that already fired: if it's gone and
# nothing was committed yet, refuse rather than resurrect a ruleset that
# was already reverted.
cmd_firewall_confirm() {
	if [ -f "$FW_RUN_DIR/committed" ]; then
		echo '{"confirmed":true,"already_confirmed":true}'
		return 0
	fi
	if [ ! -f "$FW_RUN_DIR/pending.rules" ]; then
		echo '{"error":"no pending firewall change to confirm"}'
		return 1
	fi
	local load_state
	load_state="$(systemctl show "${FW_ROLLBACK_UNIT}.timer" -p LoadState --value 2>/dev/null)"
	if [ "$load_state" != "loaded" ]; then
		echo '{"error":"confirmation window already expired; ruleset was rolled back"}'
		return 1
	fi
	touch "$FW_RUN_DIR/committed"
	systemctl stop "${FW_ROLLBACK_UNIT}.timer" "${FW_ROLLBACK_UNIT}.service" >/dev/null 2>&1 || true
	systemctl reset-failed "${FW_ROLLBACK_UNIT}.service" >/dev/null 2>&1 || true
	# Snapshot the LIVE rules (includes the guard inserts), not the
	# pending.rules the panel sent -- current.rules must reflect exactly
	# what's actually active.
	iptables-save > "$FW_ETC_DIR/current.rules"
	ensure_fw_boot_unit
	systemctl enable protean-firewall.service >/dev/null 2>&1
	echo '{"confirmed":true}'
}

# cmd_firewall_rollback: restores the pre-apply snapshot, unless
# firewall-confirm already won the race (committed marker present).
# Invoked either by the armed timer or directly as a panic button.
cmd_firewall_rollback() {
	if [ -f "$FW_RUN_DIR/committed" ]; then
		echo '{"rolled_back":false,"reason":"already confirmed"}'
		return 0
	fi
	if [ ! -f "$FW_RUN_DIR/snapshot.rules" ]; then
		echo '{"error":"no snapshot to roll back to"}'
		return 1
	fi
	iptables-restore < "$FW_RUN_DIR/snapshot.rules"
	# Remove pending.rules so fw_pending()/firewall-confirm correctly see
	# "nothing pending" afterward -- whether this ran via the armed timer
	# firing or as a direct panic-button call that bypasses the timer
	# entirely (confirmed live: without this, a confirm call made right
	# after a panic-button rollback could still succeed and persist the
	# already-reverted ruleset). Deliberately does NOT call `systemctl
	# stop` on the timer/service pair here: when this runs AS the timer-
	# fired protean-fw-rollback.service itself, stopping its own unit from
	# within is a genuine race (confirmed live -- the process can be
	# killed before finishing this cleanup, non-deterministically) and is
	# unnecessary anyway, since fw_pending() checks pending.rules'
	# existence FIRST (short-circuiting before ever consulting the
	# timer's LoadState), and a --collect unit garbage-collects itself
	# once it exits regardless. The panic-button path leaves a still-
	# armed, now-redundant timer that will fire once more later and
	# harmlessly re-restore the same already-restored snapshot.
	rm -f "$FW_RUN_DIR/pending.rules" "$FW_RUN_DIR/armed_at" "$FW_RUN_DIR/window_secs"
	echo '{"rolled_back":true}'
}

# cmd_firewall_status: read-only. Whether a change is pending confirmation
# and how many seconds remain (from the real systemd timer, not a client-
# side clock), whether a confirmed ruleset has ever been saved, and the
# live protean-fw-tagged rules currently active.
cmd_firewall_status() {
	local pending=0 remaining=0 confirmed=0
	if fw_pending; then
		pending=1
		# Computed from our own armed_at/window_secs files, not a systemd
		# timer property -- confirmed live (systemd 252) that --on-active
		# timers leave NextElapseUSecRealtime empty (it's a monotonic
		# timer, not realtime) and NextElapseUSecMonotonic gets pretty-
		# printed as a human string ("2w 3d 9h ...") rather than a raw
		# number, so neither is reliably machine-parseable across systemd
		# versions.
		if [ -f "$FW_RUN_DIR/armed_at" ] && [ -f "$FW_RUN_DIR/window_secs" ]; then
			local armed_at window_secs now_epoch
			armed_at="$(cat "$FW_RUN_DIR/armed_at")"
			window_secs="$(cat "$FW_RUN_DIR/window_secs")"
			now_epoch="$(date +%s)"
			remaining=$(( armed_at + window_secs - now_epoch ))
			[ "$remaining" -lt 0 ] && remaining=0
		fi
	fi
	[ -f "$FW_ETC_DIR/current.rules" ] && confirmed=1
	local live full
	live="$(iptables-save 2>/dev/null | grep protean-fw || true)"
	# The panel's SSH user only has passwordless sudo to this one script,
	# not to arbitrary root commands like a bare "iptables-save" -- the
	# dry-run diff needs the FULL current ruleset (not just the
	# protean-fw-tagged subset) to show what a restore would actually
	# change, so it rides along in this same read-only verb's payload.
	full="$(iptables-save 2>/dev/null || true)"
	printf '{"pending":%s,"remaining_secs":%d,"confirmed_state_saved":%s,"live_protean_rules":%s,"current_ruleset":%s}\n' \
		"$(json_bool "$pending")" "$remaining" "$(json_bool "$confirmed")" "$(json_str "$live")" "$(json_str "$full")"
}

# cmd_firewall_boot_restore: ExecStart of protean-firewall.service.
cmd_firewall_boot_restore() {
	[ -f "$FW_ETC_DIR/current.rules" ] || return 0
	command -v iptables-restore >/dev/null 2>&1 || return 0
	iptables-restore < "$FW_ETC_DIR/current.rules"
}

# cmd_service <action> <unit>: control a VPN systemd unit to save resources on
# hosts where a given VPN is not used. Whitelisted actions + unit pattern.
cmd_service() {
	local action="$1" unit="$2"
	command -v systemctl >/dev/null 2>&1 || { echo "no systemctl" >&2; return 1; }
	case "$action" in
		start|stop|restart) systemctl "$action" "$unit" ;;
		enable)
			# If $unit's underlying template/unit file is itself a
			# manually-created alias symlink (see ensure_ipsec_alias,
			# ensure_openvpn_alias -- needed where a distro's package
			# doesn't declare a native alias, e.g. RHEL's strongswan
			# has no ipsec.service alias, openSUSE's openvpn package
			# ships openvpn@.service not openvpn-server@.service),
			# systemd refuses to `enable` it directly ("Refusing to
			# operate on alias name or linked unit file") -- resolve
			# to the real target and enable THAT instead. start/stop/
			# restart against the alias name work fine as-is, only
			# enable needs this. (is-active against the alias name does
			# NOT reliably work as-is on old systemd -- see unit_active,
			# used by cmd_status/provider_service_active instead of
			# is-active directly.)
			local base="${unit%%@*}" instance="" tmpl real
			case "$unit" in
				*@*) instance="${unit#*@}" ;;
			esac
			if [ -n "$instance" ]; then
				tmpl="/etc/systemd/system/${base}@.service"
			else
				tmpl="/etc/systemd/system/${base}.service"
			fi
			if [ -L "$tmpl" ]; then
				real="$(readlink -f "$tmpl")"
				if [ -n "$instance" ]; then
					local realbase
					realbase="$(basename "$real")"
					realbase="${realbase%@.service}"
					systemctl enable --now "${realbase}@${instance}"
				else
					systemctl enable --now "$real"
				fi
			else
				systemctl enable --now "$unit"
			fi
			;;
		disable) systemctl disable --now "$unit" ;;
		*) echo "invalid action" >&2; return 2 ;;
	esac
}

# --------------------------------------------------------------------- dispatch

VALID_PROVIDER='^(wireguard|amneziawg|openvpn|ikev2|xray)$'
VALID_UNIT='^(wg-quick|awg-quick|openvpn-server|openvpn|strongswan|strongswan-starter|ipsec|xray)@?[A-Za-z0-9@._-]*$'
VALID_ACTION='^(start|stop|restart|enable|disable)$'
VALID_CIDR='^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'
VALID_FWD='^(add|del)$'
VALID_LINES='^[0-9]{1,4}$'
VALID_FW_WINDOW='^[0-9]{2,4}$'
VALID_PORT='^[0-9]{1,5}$'
VALID_FW_PORTLIST='^(tcp|udp):[0-9]{1,5}(,(tcp|udp):[0-9]{1,5}){0,31}$'
VALID_DEST_LIST='^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}(,[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}){0,63}$'

main() {
	local verb="${1:-}"
	case "$verb" in
		detect)
			cmd_detect
			;;
		install)
			local p="${2:-}"
			[[ "$p" =~ $VALID_PROVIDER ]] || { echo "invalid provider" >&2; exit 2; }
			cmd_install "$p"
			;;
		status)
			local u="${2:-}"
			[[ "$u" =~ $VALID_UNIT ]] || { echo "invalid unit" >&2; exit 2; }
			cmd_status "$u"
			;;
		service)
			local a="${2:-}" u="${3:-}"
			[[ "$a" =~ $VALID_ACTION ]] || { echo "invalid action" >&2; exit 2; }
			[[ "$u" =~ $VALID_UNIT ]] || { echo "invalid unit" >&2; exit 2; }
			cmd_service "$a" "$u"
			;;
		forward)
			local a="${2:-}" c="${3:-}"
			[[ "$a" =~ $VALID_FWD ]] || { echo "invalid action" >&2; exit 2; }
			[[ "$c" =~ $VALID_CIDR ]] || { echo "invalid cidr" >&2; exit 2; }
			cmd_forward "$a" "$c"
			;;
		subnet-nat)
			local a="${2:-}" c="${3:-}"
			[[ "$a" =~ $VALID_FWD ]] || { echo "invalid action" >&2; exit 2; }
			[[ "$c" =~ $VALID_CIDR ]] || { echo "invalid cidr" >&2; exit 2; }
			cmd_subnet_nat "$a" "$c"
			;;
		peer-forward-rules)
			local peer="${2:-}" dests="${3:-}"
			[[ "$peer" =~ $VALID_CIDR ]] || { echo "invalid peer address" >&2; exit 2; }
			[[ -z "$dests" || "$dests" =~ $VALID_DEST_LIST ]] || { echo "invalid destination list" >&2; exit 2; }
			cmd_peer_forward_rules "$peer" "$dests"
			;;
		fix-conf-perms)
			cmd_fix_conf_perms "${2:-}" "${3:-}"
			;;
		logs)
			local u="${2:-}" n="${3:-200}"
			[[ "$u" =~ $VALID_UNIT ]] || { echo "invalid unit" >&2; exit 2; }
			[[ "$n" =~ $VALID_LINES ]] || { echo "invalid lines" >&2; exit 2; }
			cmd_logs "$u" "$n"
			;;
		ensure-ip-forward)
			cmd_ensure_ip_forward
			;;
		updates-check)
			cmd_updates_check
			;;
		updates-apply)
			cmd_updates_apply
			;;
		firewall-baseline)
			cmd_firewall_baseline
			;;
		firewall-validate)
			cmd_firewall_validate
			;;
		firewall-apply)
			local w="${2:-}" sp="${3:-}" cp="${4:-}"
			[[ "$w" =~ $VALID_FW_WINDOW ]] || { echo "invalid window" >&2; exit 2; }
			[[ "$sp" =~ $VALID_PORT ]] || { echo "invalid ssh port" >&2; exit 2; }
			if [ -n "$cp" ] && [[ ! "$cp" =~ $VALID_FW_PORTLIST ]]; then
				echo "invalid critical ports" >&2
				exit 2
			fi
			cmd_firewall_apply "$w" "$sp" "$cp"
			;;
		firewall-confirm)
			cmd_firewall_confirm
			;;
		firewall-rollback)
			cmd_firewall_rollback
			;;
		firewall-status)
			cmd_firewall_status
			;;
		firewall-boot-restore)
			cmd_firewall_boot_restore
			;;
		*)
			echo "usage: $0 {detect|install <provider>|status <unit>|service <action> <unit>|forward <add|del> <cidr>|subnet-nat <add|del> <cidr>|peer-forward-rules <peer/32> [dest1,dest2,...]|fix-conf-perms <path> [owner]|logs <unit> <lines>|ensure-ip-forward|updates-check|updates-apply|firewall-baseline|firewall-validate|firewall-apply|firewall-confirm|firewall-rollback|firewall-status|firewall-boot-restore}" >&2
			exit 2
			;;
	esac
}

main "$@"
