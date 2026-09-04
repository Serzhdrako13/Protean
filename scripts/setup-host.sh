#!/usr/bin/env bash
# Interactive host setup for Protean: installs the VPN daemons the panel
# manages (WireGuard, AmneziaWG) and the ones it doesn't yet (OpenVPN,
# IKEv2/strongSwan -- package only), creates the panel's system account and
# narrow sudoers rules, wires up file permissions, and creates its database
# in an already-running Postgres container.
#
# Run as root on the target VPS -- NOT inside the panel's own container.
# Must be run interactively (not piped into bash) since it asks questions.
#
#   sudo ./setup-host.sh
#
set -uo pipefail

if [ -t 1 ]; then
	C_RESET=$'\033[0m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_BOLD=$'\033[1m'
else
	C_RESET=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_BOLD=''
fi
log()  { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
# HAD_ERROR: this script runs with `set -uo pipefail`, deliberately without
# `-e` -- an interactive setup wizard needs to keep going past an
# individual step's failure (e.g. a skippable warn()), and turning on -e
# globally would risk breaking other steps that already tolerate a
# sub-command failing on purpose. err() sets this flag instead, checked at
# the very end by print_summary/main so a real failure (confirmed live:
# setup_sudoers' own visudo validation failing, which used to print an
# err() and then main() carried on to print an unqualified success
# summary anyway) is loudly re-surfaced instead of getting lost among
# earlier scrollback, and the script's own exit code reflects it.
HAD_ERROR=0
err()  { HAD_ERROR=1; printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
title(){ printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Directory this script lives in, so it can find its sibling installer script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

confirm() {
	# confirm "question" [Y|N default]
	local prompt="$1" default="${2:-N}" suffix ans
	suffix="[y/N]"; [ "$default" = "Y" ] && suffix="[Y/n]"
	read -rp "$prompt $suffix " ans || ans=""
	ans=${ans:-$default}
	case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		err "Run as root: sudo $0"
		exit 1
	fi
}

require_tty() {
	if [ ! -t 0 ]; then
		err "This script asks interactive questions -- run it directly, don't pipe it into bash."
		exit 1
	fi
}

# ---------------------------------------------------------------- OS detect

OS_FAMILY=""   # arch | debian | rpm | suse
PKG_UPDATED=0

detect_os() {
	if [ ! -r /etc/os-release ]; then
		err "Cannot read /etc/os-release -- unsupported system."
		exit 1
	fi
	# shellcheck disable=SC1091
	. /etc/os-release

	case " ${ID:-} ${ID_LIKE:-} " in
		*" suse "*|*" opensuse "*|*" sles "*) OS_FAMILY="suse" ;;
		*" arch "*|*" archlinux "*) OS_FAMILY="arch" ;;
		*" debian "*|*" ubuntu "*)  OS_FAMILY="debian" ;;
		*" rhel "*|*" fedora "*)    OS_FAMILY="rpm" ;;
		*)
			case "${ID:-}" in
				opensuse*|sles|suse) OS_FAMILY="suse" ;;
				arch|endeavouros|manjaro|garuda|arcolinux|cachyos|artix) OS_FAMILY="arch" ;;
				debian|ubuntu|linuxmint|pop|kali|raspbian|elementary|zorin|mx|deepin) OS_FAMILY="debian" ;;
				fedora|rhel|centos|rocky|almalinux|ol|amzn|mageia) OS_FAMILY="rpm" ;;
				*) OS_FAMILY="" ;;
			esac
			;;
	esac

	if [ -z "$OS_FAMILY" ]; then
		err "Unrecognized distro (ID=${ID:-?} ID_LIKE=${ID_LIKE:-?})."
		err "Supported families: Arch, Debian/Ubuntu, RHEL/Fedora, openSUSE."
		exit 1
	fi

	if [ ! -d /run/systemd/system ]; then
		err "This host does not appear to use systemd."
		err "Protean targets systemd distros; set up VPN services manually here."
		exit 1
	fi

	log "Detected: ${PRETTY_NAME:-$ID} -> $OS_FAMILY family (systemd)"
	if have_cmd getenforce && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
		warn "SELinux is enforcing. WireGuard needs no booleans, but custom ports for OpenVPN/IKEv2 may require: semanage port -a ..."
	fi
}

pkg_install() {
	case "$OS_FAMILY" in
		arch)
			pacman -Sy --noconfirm --needed "$@"
			;;
		debian)
			if [ "$PKG_UPDATED" -eq 0 ]; then apt-get update -y; PKG_UPDATED=1; fi
			DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
			;;
		rpm)
			if have_cmd dnf; then dnf install -y "$@"; else yum install -y "$@"; fi
			;;
		suse)
			zypper --non-interactive install -y "$@"
			;;
	esac
}

# ------------------------------------------------------------- WireGuard

WG_IFACE="wg0"
WG_INSTALLED=0
WG_PORT=""

install_wireguard() {
	title "WireGuard"
	case "$OS_FAMILY" in
		arch)   pkg_install wireguard-tools ;;
		debian) pkg_install wireguard ;;
		rpm)    pkg_install wireguard-tools ;;
	esac

	if ! have_cmd wg || ! have_cmd wg-quick; then
		err "wg/wg-quick not found after install -- WireGuard setup failed."
		return 1
	fi
	modprobe wireguard 2>/dev/null || warn "Could not load the wireguard kernel module -- if this kernel predates 5.6, install a dkms/module package for it."

	local conf_dir="/etc/wireguard" conf
	conf="$conf_dir/${WG_IFACE}.conf"
	mkdir -p "$conf_dir"
	chmod 700 "$conf_dir"

	if [ -f "$conf" ]; then
		log "Config $conf already exists, leaving it as-is."
		WG_PORT=$(sed -n 's/^ListenPort *= *//p' "$conf" | head -1)
	else
		local wg_addr wg_port priv pub
		read -rp "Server tunnel address (CIDR) [10.10.0.1/24]: " wg_addr
		wg_addr=${wg_addr:-10.10.0.1/24}
		read -rp "WireGuard listen port [51820]: " wg_port
		wg_port=${wg_port:-51820}

		priv=$(wg genkey)
		pub=$(printf '%s' "$priv" | wg pubkey)

		cat > "$conf" <<-EOF
			[Interface]
			PrivateKey = $priv
			Address = $wg_addr
			ListenPort = $wg_port
		EOF
		chmod 600 "$conf"
		WG_PORT="$wg_port"
		log "Generated $conf"
		log "Server public key: $pub"
	fi

	if systemctl enable --now "wg-quick@${WG_IFACE}" 2>/dev/null; then
		log "wg-quick@${WG_IFACE} enabled and started."
	else
		warn "Could not start wg-quick@${WG_IFACE} -- check: journalctl -u wg-quick@${WG_IFACE}"
	fi

	WG_INSTALLED=1
}

# ------------------------------------------------------------- AmneziaWG

AWG_IFACE="awg0"
AWG_INSTALLED=0
AWG_PORT=""

install_amneziawg() {
	title "AmneziaWG"
	case "$OS_FAMILY" in
		arch)
			if have_cmd yay; then
				sudo -u "${SUDO_USER:-root}" yay -S --noconfirm amneziawg-tools amneziawg-dkms || true
			elif have_cmd paru; then
				sudo -u "${SUDO_USER:-root}" paru -S --noconfirm amneziawg-tools amneziawg-dkms || true
			else
				warn "No AUR helper (yay/paru) found. Install one, then run:"
				warn "  yay -S amneziawg-tools amneziawg-dkms"
				warn "and re-run this script to configure AmneziaWG."
			fi
			;;
		debian|rpm)
			warn "No official AmneziaWG package for this distro family."
			warn "Install the 'awg' and 'awg-quick' binaries manually (see the AmneziaWG"
			warn "project's own install docs), make sure they're on PATH, then re-run"
			warn "this script and choose AmneziaWG again."
			;;
	esac

	if ! have_cmd awg || ! have_cmd awg-quick; then
		warn "awg/awg-quick not found -- skipping AmneziaWG configuration."
		return 1
	fi

	local conf_dir="/etc/amnezia/amneziawg" conf
	conf="$conf_dir/${AWG_IFACE}.conf"
	mkdir -p "$conf_dir"
	chmod 700 "$conf_dir"

	if [ -f "$conf" ]; then
		log "Config $conf already exists, leaving it as-is."
		AWG_PORT=$(sed -n 's/^ListenPort *= *//p' "$conf" | head -1)
	else
		local awg_addr awg_port priv pub
		read -rp "AmneziaWG tunnel address (CIDR) [10.20.0.1/24]: " awg_addr
		awg_addr=${awg_addr:-10.20.0.1/24}
		read -rp "AmneziaWG listen port [51821]: " awg_port
		awg_port=${awg_port:-51821}

		priv=$(awg genkey)
		pub=$(printf '%s' "$priv" | awg pubkey)

		cat > "$conf" <<-EOF
			[Interface]
			PrivateKey = $priv
			Address = $awg_addr
			ListenPort = $awg_port
			Jc = 4
			Jmin = 40
			Jmax = 70
			S1 = 0
			S2 = 0
			H1 = 1
			H2 = 2
			H3 = 3
			H4 = 4
		EOF
		chmod 600 "$conf"
		AWG_PORT="$awg_port"
		log "Generated $conf"
		log "Server public key: $pub"
		warn "Jc/Jmin/Jmax/S1/S2/H1-4 are placeholders and must match on every client -- adjust via the panel's server settings page if you change them."
	fi

	if systemctl enable --now "awg-quick@${AWG_IFACE}" 2>/dev/null; then
		log "awg-quick@${AWG_IFACE} enabled and started."
	else
		warn "Could not start awg-quick@${AWG_IFACE} -- check: journalctl -u awg-quick@${AWG_IFACE}"
	fi

	AWG_INSTALLED=1
}

# ------------------------------------------------------- OpenVPN / IKEv2

OVPN_INSTALLED=0

install_openvpn() {
	title "OpenVPN"
	case "$OS_FAMILY" in
		arch)   pkg_install openvpn ;;
		debian) pkg_install openvpn ;;
		rpm)    pkg_install openvpn ;;
		suse)   pkg_install openvpn ;;
	esac
	if have_cmd openvpn; then
		OVPN_INSTALLED=1
		log "OpenVPN installed. Provision the server from the panel (Set up OpenVPN server)."
	else
		warn "openvpn not found after install."
	fi
}

IKEV2_INSTALLED=0

install_ikev2() {
	title "strongSwan / IKEv2"
	case "$OS_FAMILY" in
		arch)   pkg_install strongswan ;;
		debian) pkg_install strongswan strongswan-swanctl strongswan-pki ;;
		rpm)    pkg_install strongswan ;;
		suse)   pkg_install strongswan ;;
	esac
	if have_cmd swanctl || have_cmd ipsec; then
		IKEV2_INSTALLED=1
		log "strongSwan installed. Provision from the panel (Set up IKEv2 server)."
	else
		warn "strongSwan/swanctl not found after install."
	fi
}

# --------------------------------------------------------- panel account

PANEL_USER="protean"
PANEL_GROUP="protean-conf"
PANEL_KEY_DIR="/root/protean-deploy"
PANEL_SSH_KEY_PATH=""

setup_panel_account() {
	title "Panel system account"

	if id "$PANEL_USER" &>/dev/null; then
		log "System user '$PANEL_USER' already exists."
	else
		# A real shell, not nologin: sshd runs `<shell> -c '<command>'` to
		# execute the panel's remote commands, so nologin would silently
		# break every SSH call the panel makes.
		useradd --system --create-home --shell /bin/bash "$PANEL_USER"
		log "Created system user '$PANEL_USER'."
	fi

	groupadd -f "$PANEL_GROUP"
	usermod -aG "$PANEL_GROUP" "$PANEL_USER"

	local ssh_dir="/home/$PANEL_USER/.ssh"
	mkdir -p "$ssh_dir"
	mkdir -p "$PANEL_KEY_DIR"
	chmod 700 "$PANEL_KEY_DIR"

	local key_path="$PANEL_KEY_DIR/id_ed25519"
	if [ -f "$key_path" ]; then
		log "Reusing existing panel SSH key at $key_path"
	else
		ssh-keygen -t ed25519 -N "" -C "protean" -f "$key_path" >/dev/null
		log "Generated panel SSH key at $key_path"
	fi

	touch "$ssh_dir/authorized_keys"
	if ! grep -qF "$(cat "${key_path}.pub")" "$ssh_dir/authorized_keys" 2>/dev/null; then
		cat "${key_path}.pub" >> "$ssh_dir/authorized_keys"
		log "Added panel public key to $ssh_dir/authorized_keys"
	fi
	chmod 700 "$ssh_dir"
	chmod 600 "$ssh_dir/authorized_keys"
	chown -R "$PANEL_USER:$PANEL_USER" "$ssh_dir"

	PANEL_SSH_KEY_PATH="$key_path"

	if grep -qE '^\s*AllowUsers\b' /etc/ssh/sshd_config 2>/dev/null && \
	   ! grep -E '^\s*AllowUsers\b' /etc/ssh/sshd_config | grep -qw "$PANEL_USER"; then
		warn "sshd_config has an AllowUsers directive that doesn't list '$PANEL_USER' -- add it or SSH login for the panel will be refused."
	fi
}

INSTALLER_DIR="/usr/local/lib/protean"
INSTALLER_PATH="${INSTALLER_DIR}/protean-installer.sh"

install_installer_script() {
	title "Panel installer script"
	local src="${SCRIPT_DIR}/protean-installer.sh"
	if [ ! -f "$src" ]; then
		warn "protean-installer.sh not found next to this script -- install-from-panel will be unavailable."
		return 1
	fi
	install -d -m 0755 -o root -g root "$INSTALLER_DIR"
	# Root-owned, not writable by the panel user: this is what makes the
	# NOPASSWD sudo grant on this single path safe.
	install -m 0755 -o root -g root "$src" "$INSTALLER_PATH"
	log "Installed $INSTALLER_PATH (root:root 0755)"
}

setup_sudoers() {
	title "Sudoers"
	local sudoers_file="/etc/sudoers.d/protean"
	local systemctl_bin cmds=()
	systemctl_bin=$(command -v systemctl)

	# The panel always needs to run the root-owned installer (for
	# install-from-panel and host detection). Its arguments are whitelisted
	# inside the script, so this single path is the whole privileged surface.
	if [ -f "$INSTALLER_PATH" ]; then
		cmds+=("$INSTALLER_PATH")

		# Self-heal (internal/vpn/installer.go's refreshScript): when the
		# panel gains a new verb but this on-host copy predates it, it
		# pushes a fresh copy via `sudo tee <path>` + `sudo chmod 750
		# <path>` and retries. Without these two exact grants self-heal has
		# NEVER actually worked -- confirmed live 2026-09-04, it silently
		# failed on every stale-script encounter since the mechanism was
		# introduced, always surfacing the original "usage: ..." error
		# instead. Scoped to the literal installer path, matching the
		# comment below: this must never become a blanket tee/chmod grant.
		local tee_bin chmod_bin
		tee_bin=$(command -v tee)
		chmod_bin=$(command -v chmod)
		if [ -n "$tee_bin" ] && [ -n "$chmod_bin" ]; then
			cmds+=("${tee_bin} ${INSTALLER_PATH}" "${chmod_bin} 750 ${INSTALLER_PATH}")
		else
			warn "tee/chmod not found on PATH -- self-heal for a stale installer script will not work until this is fixed by hand"
		fi
	fi

	# wg/awg grants are scoped to `show *`/`set *` -- the only two
	# invocation shapes internal/vpn/wgfamily ever runs (`wg show <if>
	# dump`, `wg set <if> peer ...`). No bare wg-quick/awg-quick grant:
	# wgfamily never calls it directly (interface restarts go through
	# `systemctl restart wg-quick@*` below, which is scoped to a FIXED
	# unit name resolved by systemd, not an admin-choosable path) -- a
	# bare `sudo wg-quick up <anything>` grant would let anyone with the
	# panel's SSH key point wg-quick at a file THEY control instead of the
	# real wg0.conf, and wg-quick's own PostUp directive runs as a shell
	# command as root, making that a straight root shell. Found live via
	# an Opus-driven audit 2026-09-04, alongside S1-S5 in the same pass.
	if [ "$WG_INSTALLED" = "1" ]; then
		cmds+=("$(command -v wg) show *" "$(command -v wg) set *" "${systemctl_bin} restart wg-quick@*")
	fi
	if [ "$AWG_INSTALLED" = "1" ]; then
		cmds+=("$(command -v awg) show *" "$(command -v awg) set *" "${systemctl_bin} restart awg-quick@*")
	fi
	# The mesh page restarts interfaces to apply forwarding rules; allow it
	# even before an interface is up so forwarding can be enabled later.
	cmds+=("${systemctl_bin} restart wg-quick@*" "${systemctl_bin} restart awg-quick@*")
	# OpenVPN/strongSwan provisioning (panel EnsureServer + service control).
	# strongSwan is managed through the "ipsec" service alias (not
	# "strongswan"/"strongswan-starter" directly) -- see ikev2.Options in
	# internal/servers/manager.go for why: systemd resolves the alias to
	# whatever the real unit is actually named on this distro, so a single
	# wildcard here covers every strongSwan packaging variant.
	cmds+=(
		"${systemctl_bin} enable --now openvpn-server@*" "${systemctl_bin} restart openvpn-server@*"
		"${systemctl_bin} enable --now ipsec*" "${systemctl_bin} restart ipsec*"
		"${systemctl_bin} enable --now xray" "${systemctl_bin} restart xray"
	)
	# IKEv2 status + config load -- internal/vpn/ikev2 only ever runs
	# these exact two invocations (no variable arguments at all), so this
	# grants them literally rather than a bare swanctl binary that could
	# run any other swanctl subcommand as root.
	if have_cmd swanctl; then
		local swanctl_bin
		swanctl_bin=$(command -v swanctl)
		cmds+=("${swanctl_bin} --list-sas" "${swanctl_bin} --load-all")
	fi

	if [ ${#cmds[@]} -eq 0 ]; then
		warn "Nothing to grant sudo for -- skipping."
		return 0
	fi

	{
		echo "# Managed by Protean's setup-host.sh."
		echo "# Narrow NOPASSWD rules: the root-owned installer (whitelisted args"
		echo "# internally), wg/awg, and interface restarts. Do not broaden this"
		echo "# file by hand -- add a separate one so re-runs don't clobber it."
		printf 'Cmnd_Alias PROTEAN_CMDS = %s\n' "$(IFS=,; echo "${cmds[*]}")"
		echo "${PANEL_USER} ALL=(root) NOPASSWD: PROTEAN_CMDS"
	} > "${sudoers_file}.new"

	if visudo -cf "${sudoers_file}.new"; then
		mv "${sudoers_file}.new" "$sudoers_file"
		chmod 440 "$sudoers_file"
		log "Installed $sudoers_file"
	else
		err "Generated sudoers rule failed validation -- NOT installed. Left at ${sudoers_file}.new for inspection."
	fi
}

setup_conf_permissions() {
	title "Config file permissions"
	# The panel's SSH user needs to read/write the exact conf file it
	# manages -- including the server's own private key, which lives in
	# that same file. That's an explicit, documented trade-off (see
	# DEPLOYMENT.md), not an oversight: it's what lets the panel edit
	# [Peer] blocks without going through sudo for every file operation.
	if [ "$WG_INSTALLED" = "1" ]; then
		local f="/etc/wireguard/${WG_IFACE}.conf"
		if [ -f "$f" ]; then
			# The directory itself was created 0700 root:root by
			# install_wireguard -- `chmod g+x` alone (the old version of
			# this script) grants the GROUP execute bit, but the group is
			# still root, not $PANEL_GROUP, so it was a complete no-op:
			# the panel could never even traverse into /etc/wireguard to
			# reach a file it otherwise had correct perms on. chgrp first.
			# setgid (2750) so any conf a future interface add creates
			# inherits the group automatically, matching the convention
			# already used below for openvpn/swanctl/xray.
			chgrp "$PANEL_GROUP" /etc/wireguard
			chmod 2750 /etc/wireguard
			chgrp "$PANEL_GROUP" "$f"
			chmod 660 "$f"
			log "Granted group '$PANEL_GROUP' read/write on $f"
		fi
	fi
	if [ "$AWG_INSTALLED" = "1" ]; then
		local f="/etc/amnezia/amneziawg/${AWG_IFACE}.conf"
		if [ -f "$f" ]; then
			chgrp "$PANEL_GROUP" /etc/amnezia/amneziawg
			chmod 2750 /etc/amnezia/amneziawg
			chgrp "$PANEL_GROUP" "$f"
			chmod 660 "$f"
			log "Granted group '$PANEL_GROUP' read/write on $f"
		fi
	fi
	if [ "$OVPN_INSTALLED" = "1" ]; then
		# The panel provisions OpenVPN by writing ca/cert/key/tls-crypt/conf
		# here, without sudo -- so grant the panel group ownership of the
		# server dir. (Server private key lives here; same documented
		# trade-off as the wg conf.) The actual per-instance ccd dir is
		# `ccd-<instance name>` (internal/servers/manager.go), created on
		# demand by the panel's own mkdir -- a bare "ccd" here was always
		# dead weight (nothing ever reads/writes it) and is left out now;
		# the real ccd-<name> dir self-heals correct group ownership on its
		# own via setgid on this parent (verified live), no separate grant
		# needed. /etc/openvpn itself (not just .../server) is also listed:
		# most distros leave it world-traversable, but ALT Linux's openvpn
		# package creates it 750 root:openvpn -- protean isn't in that
		# group, so it couldn't even traverse into its own correctly-
		# permissioned server/ccd-* subdirectories underneath (confirmed
		# live; sshexec.provisionScript already carries this fix, this
		# backports it to the manual setup-host.sh path).
		# /etc/openvpn itself only needs GROUP TRAVERSE (2750), not write --
		# the panel never writes directly into it, only into server/ below.
		install -d -m 2750 -g "$PANEL_GROUP" /etc/openvpn
		install -d -m 2770 -g "$PANEL_GROUP" /etc/openvpn/server
		chgrp -R "$PANEL_GROUP" /etc/openvpn/server
		log "Prepared /etc/openvpn/server group-writable by '$PANEL_GROUP'"
	fi
	if [ "$IKEV2_INSTALLED" = "1" ]; then
		# Same model for strongSwan: the panel writes CA/cert/key/conf under
		# /etc/swanctl without sudo. x509crl (CRL revocation) is listed
		# explicitly, not left to the blanket chgrp -R below: the
		# strongswan-swanctl package creates it 0755 root:root (confirmed
		# live), and chgrp -R only fixes the GROUP -- mode 755's group bits
		# are r-x, no write, so without this the panel could read but never
		# actually write a revoked client's crl.pem, and revocation would
		# silently never take effect. Found live via an Opus-driven audit.
		install -d -m 2770 -g "$PANEL_GROUP" \
			/etc/swanctl /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private /etc/swanctl/conf.d /etc/swanctl/x509crl
		chgrp -R "$PANEL_GROUP" /etc/swanctl
		log "Prepared /etc/swanctl group-writable by '$PANEL_GROUP'"
	fi
	if have_cmd xray; then
		# The panel writes /usr/local/etc/xray/config.json (Xray-install layout)
		# without sudo -> grant the panel group ownership of the config dir.
		install -d -m 2770 -g "$PANEL_GROUP" /usr/local/etc/xray
		chgrp -R "$PANEL_GROUP" /usr/local/etc/xray 2>/dev/null || true
		log "Prepared /usr/local/etc/xray group-writable by '$PANEL_GROUP'"
	fi
}

# ------------------------------------------------------------ system tuning

enable_ip_forwarding() {
	title "IPv4 forwarding"
	confirm "Enable net.ipv4.ip_forward=1 (needed to route between sites through this host)?" Y || return 0
	if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "1" ] && grep -q '^net.ipv4.ip_forward' /etc/sysctl.d/99-protean.conf 2>/dev/null; then
		log "Already enabled and persisted."
		return 0
	fi
	echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-protean.conf
	sysctl -p /etc/sysctl.d/99-protean.conf >/dev/null
	log "Enabled and persisted in /etc/sysctl.d/99-protean.conf"
}

firewall_hints() {
	title "Firewall"
	local ports=()
	[ "$WG_INSTALLED" = "1" ] && [ -n "$WG_PORT" ] && ports+=("${WG_PORT}/udp")
	[ "$AWG_INSTALLED" = "1" ] && [ -n "$AWG_PORT" ] && ports+=("${AWG_PORT}/udp")
	[ ${#ports[@]} -eq 0 ] && return 0

	log "Make sure these ports are reachable from the internet:"
	for p in "${ports[@]}"; do echo "    $p"; done

	if have_cmd ufw; then
		echo "  Detected ufw. Example:"
		for p in "${ports[@]}"; do echo "    ufw allow ${p}"; done
	elif have_cmd firewall-cmd; then
		echo "  Detected firewalld. Example:"
		for p in "${ports[@]}"; do echo "    firewall-cmd --permanent --add-port=${p}"; done
		echo "    firewall-cmd --reload"
	elif have_cmd nft; then
		echo "  Detected nftables -- add rules matching your existing ruleset."
	else
		echo "  No recognized firewall manager found -- check iptables/nft rules by hand."
	fi
	warn "Not applying firewall changes automatically: a mistake here can lock you out over SSH."
}

# --------------------------------------------------------------- postgres

DATABASE_URL=""
PG_NETWORK=""

setup_postgres() {
	title "Postgres database"
	confirm "Create the panel's database inside an existing Postgres container now?" Y || return 0

	if ! have_cmd docker; then
		warn "docker not found -- skipping. Create the database by hand (see DEPLOYMENT.md)."
		return 1
	fi

	local containers
	containers=$(docker ps --format '{{.Names}}  ({{.Image}})' 2>/dev/null | grep -i postgres || true)
	if [ -n "$containers" ]; then
		echo "Running containers that look like Postgres:"
		echo "$containers"
	fi
	local pg_container
	read -rp "Postgres container name: " pg_container
	if [ -z "$pg_container" ] || ! docker inspect "$pg_container" >/dev/null 2>&1; then
		warn "No such container -- skipping DB setup."
		return 1
	fi

	local pg_admin pg_db pg_pass pg_pass_input
	read -rp "Postgres admin user [postgres]: " pg_admin
	pg_admin=${pg_admin:-postgres}
	read -rp "Database/role name for the panel [protean]: " pg_db
	pg_db=${pg_db:-protean}
	pg_pass=$(openssl rand -hex 20)
	read -rp "Panel DB password [random, press enter to accept]: " pg_pass_input
	[ -n "$pg_pass_input" ] && pg_pass="$pg_pass_input"

	if docker exec -i "$pg_container" psql -U "$pg_admin" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${pg_db}'" 2>/dev/null | grep -q 1; then
		log "Role '$pg_db' already exists -- leaving its password as-is."
	else
		if docker exec -i "$pg_container" psql -U "$pg_admin" -c "CREATE ROLE ${pg_db} LOGIN PASSWORD '${pg_pass}';"; then
			log "Created role '$pg_db'."
		else
			err "Failed to create role -- check the admin user/container name."
			return 1
		fi
	fi

	if docker exec -i "$pg_container" psql -U "$pg_admin" -tAc "SELECT 1 FROM pg_database WHERE datname='${pg_db}'" 2>/dev/null | grep -q 1; then
		log "Database '$pg_db' already exists."
	else
		if docker exec -i "$pg_container" psql -U "$pg_admin" -c "CREATE DATABASE ${pg_db} OWNER ${pg_db};"; then
			log "Created database '$pg_db'."
		else
			err "Failed to create database."
			return 1
		fi
	fi

	PG_NETWORK=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$pg_container" 2>/dev/null | awk '{print $1}')
	[ -n "$PG_NETWORK" ] && log "Postgres container is on docker network '$PG_NETWORK' -- use it as postgres-net in docker-compose.yml."

	DATABASE_URL="postgres://${pg_db}:${pg_pass}@${pg_container}:5432/${pg_db}?sslmode=disable"
}

# ------------------------------------------------------------------ .env

generate_env() {
	title "Panel .env"
	local out="$PANEL_KEY_DIR/panel.env"
	local secret_key session_secret admin_user admin_pass admin_pass_input public_host

	secret_key=$(openssl rand -hex 32)
	session_secret=$(openssl rand -hex 32)

	read -rp "Admin username [admin]: " admin_user
	admin_user=${admin_user:-admin}
	admin_pass=$(openssl rand -hex 12)
	read -rp "Admin password [random, press enter to accept]: " admin_pass_input
	[ -n "$admin_pass_input" ] && admin_pass="$admin_pass_input"

	read -rp "This VPS's public IP/hostname (client Endpoint): " public_host

	# Capture the host's SSH public key so the panel can pin it (prevents
	# MITM). Prefer ed25519; fall back to whatever ssh-keyscan returns.
	local host_key=""
	if have_cmd ssh-keyscan; then
		host_key=$(ssh-keyscan -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | head -1 | cut -d' ' -f2-)
		[ -z "$host_key" ] && host_key=$(ssh-keyscan 127.0.0.1 2>/dev/null | grep -v '^#' | head -1 | cut -d' ' -f2-)
	fi
	[ -z "$host_key" ] && warn "Could not read host SSH key; leaving SSH_HOST_KEY empty (panel will trust-on-first-use and log it)."

	cat > "$out" <<-EOF
		DATABASE_URL=${DATABASE_URL:-postgres://protean:CHANGEME@postgres:5432/protean?sslmode=disable}
		SSH_HOST=host.docker.internal
		SSH_PORT=22
		SSH_USER=${PANEL_USER}
		SSH_HOST_KEY=${host_key}
		SESSION_SECRET=${session_secret}
		SECRET_KEY=${secret_key}
		ADMIN_USERNAME=${admin_user}
		ADMIN_PASSWORD=${admin_pass}
		PUBLIC_HOST=${public_host}
		WG_INTERFACE=${WG_IFACE}
		AWG_INTERFACE=${AWG_IFACE}
	EOF
	chmod 600 "$out"
	log "Wrote $out"
	if [ -n "$host_key" ]; then
		warn "SSH_HOST_KEY was scanned from 127.0.0.1. If the panel connects via host.docker.internal to a different host key, re-scan the right address."
	fi
}

print_summary() {
	if [ "$HAD_ERROR" -eq 1 ]; then
		title "Done, WITH ERRORS"
		err "One or more steps above failed (look for [x] lines in the output above)."
		err "The panel may not work correctly until these are fixed by hand and this script is re-run."
	else
		title "Done"
	fi
	cat <<-EOF
	Generated in ${PANEL_KEY_DIR}:
	  id_ed25519, id_ed25519.pub  -- panel's SSH keypair (public key already
	                                 added to ${PANEL_USER}'s authorized_keys)
	  panel.env                   -- ready-to-use .env for the panel

	Next steps, from wherever you'll run docker compose (usually this same host):
	  1. Copy id_ed25519 to ./secrets/id_ed25519 (chmod 600) next to docker-compose.yml.
	  2. Copy panel.env to ./.env next to docker-compose.yml.
	  3. If a Postgres network was detected, set it as postgres-net in docker-compose.yml${PG_NETWORK:+ (detected: $PG_NETWORK)}.
	  4. docker compose build && docker compose up -d
	  5. Once it's up, delete ${PANEL_KEY_DIR} from this host -- it holds a copy
	     of the private key and secrets that only need to exist transiently here.

	See DEPLOYMENT.md for the full checklist and what to double-check by hand.
	EOF
}

# --------------------------------------------------------------------- main

main() {
	require_root
	require_tty
	detect_os
	confirm "Continue with setup on this host?" Y || exit 0

	echo
	log "VPNs can also be installed later from the panel's Install page."
	confirm "Install/configure WireGuard now? (panel manages this fully)" Y && install_wireguard
	confirm "Install/configure AmneziaWG now? (panel manages this fully, packaging varies by distro)" N && install_amneziawg
	confirm "Install OpenVPN now? (package only -- panel doesn't manage it yet)" N && install_openvpn
	confirm "Install strongSwan/IKEv2 now? (package only -- panel doesn't manage it yet)" N && install_ikev2

	# The panel account, installer script, and sudoers are always set up:
	# the panel needs them even when no VPN is installed yet (so VPNs can be
	# installed from the panel later).
	setup_panel_account
	install_installer_script
	setup_sudoers
	setup_conf_permissions

	enable_ip_forwarding
	firewall_hints
	setup_postgres

	if [ -n "$PANEL_SSH_KEY_PATH" ]; then
		generate_env
	else
		warn "No panel account was set up -- skipping .env generation."
	fi

	print_summary
	[ "$HAD_ERROR" -eq 0 ]
}

main "$@"
