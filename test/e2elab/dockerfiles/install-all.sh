#!/bin/bash
# Test-only helper (not part of the shipped product): calls
# protean-installer.sh's own install_wireguard/install_amneziawg/
# install_openvpn/install_ikev2/install_xray functions directly, rather
# than through its `install <provider>` CLI verb.
#
# Why: `cmd_install` gates on HAS_SYSTEMD (checks for /run/systemd/system),
# a real and correct guard for actual deployments -- but during `docker
# build`, systemd isn't running as PID 1 yet (only installed), so that
# check is a build-time-only false negative, not a real distro-support
# gap. Sourcing everything BEFORE the script's own trailing `main "$@"`
# (which would otherwise immediately dispatch/exit) lets this call the
# exact same per-distro install functions the real CLI path uses, with
# only that one inapplicable-at-build-time precondition skipped.
set -e
source <(sed '$d' /usr/local/lib/protean/protean-installer.sh)
detect_os

install_wireguard
# AmneziaWG's install path needs a PPA (Ubuntu)/COPR (RPM)/AUR helper
# (Arch) that may not resolve on every base image -- expected to fail on
# several distros; best-effort, not a hard requirement.
install_amneziawg || echo "[i] amneziawg install skipped/failed (expected on some distros)"
install_openvpn
install_ikev2
install_xray

# The official Xray installer auto-enables its unit. In production
# "install xray" is an admin action that only ever happens after a host
# is already bootstrapped (the "protean" service account already exists);
# here it runs at image *build* time, before the "protean" account
# exists, which the go embedded installer only creates over SSH at
# container *runtime*. Left enabled, xray would try to autostart at
# container boot, fail on the not-yet-created user, and hit systemd's
# start-limit lockout before bootstrap ever gets a chance to fix it --
# confirmed live on Arch. Disabling here just resets the test image back
# to the same state a real freshly-provisioned host is in before any
# provider install: the panel's own Apply()/EnsureServer() re-enables it
# for real once "protean" actually exists.
systemctl disable xray 2>/dev/null || true
