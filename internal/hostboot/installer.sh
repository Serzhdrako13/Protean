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
#
# Keep this script dependency-free (POSIX-ish bash) and side-effect-free
# except for the explicit install actions.
set -uo pipefail

# --------------------------------------------------------------- OS detection

OS_FAMILY=""     # debian | rpm | arch | suse
PKG_MANAGER=""   # apt | dnf | yum | pacman | zypper
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
		*)
			case "${ID:-}" in
				opensuse*|sles|suse) OS_FAMILY="suse" ;;
				arch|endeavouros|manjaro|garuda|arcolinux|cachyos|artix) OS_FAMILY="arch" ;;
				debian|ubuntu|linuxmint|pop|kali|raspbian|elementary|zorin|mx|deepin) OS_FAMILY="debian" ;;
				fedora|rhel|centos|rocky|almalinux|ol|amzn|mageia) OS_FAMILY="rpm" ;;
			esac
			;;
	esac

	if   command -v apt-get >/dev/null 2>&1 && [ "$OS_FAMILY" = "debian" ]; then PKG_MANAGER="apt"
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
				suse) return 1 ;;                       # no known package
			esac
			;;
		wireguard|openvpn|ikev2) return 0 ;;
		xray) return 0 ;;   # installed via the official get-xray script
		*) return 1 ;;
	esac
}

# --------------------------------------------------------------------- detect

json_bool() { if [ "$1" -eq 1 ] 2>/dev/null || [ "$1" = "true" ]; then printf 'true'; else printf 'false'; fi; }

provider_json() {
	local p="$1" inst=false able=false
	provider_installed "$p" && inst=true
	provider_installable "$p" && able=true
	printf '"%s":{"installed":%s,"installable":%s}' "$p" "$inst" "$able"
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
		dnf)    dnf install -y "$@" ;;
		yum)    yum install -y "$@" ;;
		pacman) pacman -Sy --noconfirm --needed "$@" ;;
		zypper) zypper --non-interactive install -y "$@" ;;
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
		apt)    pkg_install wireguard ;;
		*)      pkg_install wireguard-tools ;;
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
			if add-apt-repository -y ppa:amnezia/ppa 2>/dev/null; then
				apt-get update -y
				pkg_install amneziawg amneziawg-tools
			else
				echo "[!] Could not add ppa:amnezia/ppa (expected on non-Ubuntu Debian)." >&2
				echo "    Add the AmneziaWG DEB822 repo manually, then re-run install." >&2
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
	case "$PKG_MANAGER" in
		apt|dnf|yum|pacman) pkg_install openvpn easy-rsa ;;
		zypper)             pkg_install openvpn easy-rsa ;;
	esac
	echo "[i] OpenVPN installed but not configured -- the panel does not manage it yet."
	provider_installed openvpn
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
	provider_installed ikev2
}

install_xray() {
	# Official installer (systemd service + /usr/local/bin/xray). Needs curl.
	have curl || pkg_install curl
	bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
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
	if [ $rc -eq 0 ]; then echo "[+] $provider installed."; else echo "[x] $provider install failed." >&2; fi
	return $rc
}

cmd_status() {
	local unit="$1"
	if ! command -v systemctl >/dev/null 2>&1; then echo "unknown"; return 0; fi
	if systemctl is-active --quiet "$unit"; then echo "active"; else echo "inactive"; fi
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

# cmd_service <action> <unit>: control a VPN systemd unit to save resources on
# hosts where a given VPN is not used. Whitelisted actions + unit pattern.
cmd_service() {
	local action="$1" unit="$2"
	command -v systemctl >/dev/null 2>&1 || { echo "no systemctl" >&2; return 1; }
	case "$action" in
		start|stop|restart) systemctl "$action" "$unit" ;;
		enable)  systemctl enable --now "$unit" ;;
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
		logs)
			local u="${2:-}" n="${3:-200}"
			[[ "$u" =~ $VALID_UNIT ]] || { echo "invalid unit" >&2; exit 2; }
			[[ "$n" =~ $VALID_LINES ]] || { echo "invalid lines" >&2; exit 2; }
			cmd_logs "$u" "$n"
			;;
		*)
			echo "usage: $0 {detect|install <provider>|status <unit>|service <action> <unit>|forward <add|del> <cidr>|logs <unit> <lines>}" >&2
			exit 2
			;;
	esac
}

main "$@"
