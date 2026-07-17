# Integration/E2E lab

A real systemd container standing in for a fresh VPS: the panel's own code
(`internal/sshexec.BootstrapHost`, `internal/vpn/openvpn`,
`internal/vpn/ikev2`, `internal/vpn/xray`, `internal/vpn.Installer`) drives
it over real SSH exactly like a real "Add server" + provisioning flow
would, and the tests assert real outcomes — a revoked certificate is
actually rejected by a real CRL (parsed with `pki.ParseCRL`, not just "a
file got written"), a systemd unit is actually `active`, `ip_forward`
actually flips in `/proc`/`sysctl`.

This is deliberately **not** part of the normal fast test suite (`go test
./...`, no build tag) — it needs Docker with `--privileged` container
support and takes a few minutes (booting systemd, starting real
OpenVPN/strongSwan/Xray). It's gated behind the `e2elab` build tag AND the
`PROTEAN_E2ELAB=1` environment variable, and runs in CI only as a nightly
scheduled job / manual `workflow_dispatch`, never on a normal push/PR (see
`.github/workflows/ci.yml`'s `e2e-lab` job).

## Running it locally

```sh
# Default: apt/Debian 12.
PROTEAN_E2ELAB=1 go test -tags e2elab ./test/e2elab/... -v -timeout 15m

# Any other distro in the matrix below: point at its Dockerfile template
# and pick a base image (any tag from that family works, not just the
# one shown -- these are the ones this pass actually ran live).
E2ELAB_DOCKERFILE=test/e2elab/dockerfiles/dnf.Dockerfile \
E2ELAB_BASE_IMAGE=rockylinux:9 \
PROTEAN_E2ELAB=1 go test -tags e2elab ./test/e2elab/... -v -timeout 15m
```

`E2ELAB_KEEP_CONTAINER=1` skips the teardown `docker rm -f` for
post-mortem debugging (`docker exec`/`journalctl` into the still-running
container after the test finishes or fails).

Requires:
- Docker able to run a `--privileged --cgroupns=host` container with
  systemd as PID 1 (the image `CMD`s `/sbin/init`) — confirmed live on a
  cgroup v2 host: `--cgroupns=host` is required, the default
  `cgroupns=private` leaves systemd unable to get PID 1 delegation at all
  (the container just exits immediately with no output). Well-established
  elsewhere (e.g. Ansible Molecule tests use the same recipe).
- Port 2222 free on the host (the container's sshd is published there).

The suite builds the image, boots one container, bootstraps it, runs every
test against that single shared host (a realistic single-VPS deployment
running multiple protocols at once, and simpler than juggling several
containers), then tears it down — even on failure (`docker rm -f` runs via
`TestMain`'s deferred cleanup).

## What's covered, and what isn't

Covered: OpenVPN and IKEv2 full lifecycle (`EnsureServer` → `AddPeer` →
`RemovePeer` → real CRL check), Xray (`Apply` → client add/remove → real
generated `config.json` inspected on the host), `ip_forward` re-check
(`vpn.Installer.EnsureIPForward`), and SSH-failure handling (stopping the
container mid-operation and confirming a clean error, not a hang).

Not covered here (explicit, not silently missing): WireGuard/AmneziaWG —
already has a real (non-mock) test via
`internal/vpn/wgfamily/integration_test.go` (`//go:build integration`, a
real network namespace, root-gated), which this lab doesn't duplicate.
Also out of scope for this pass: driving the same scenarios through the
real HTTP API + a real Postgres instead of the in-memory fake `Store`/
`Sealer` used here — the DB layer already has its own dbtest coverage, and
this lab's job is proving the HOST side for real; wiring the full stack
together end-to-end (API → DB → SSH → real host) is a natural next
increment, not this one.

## Distro matrix

Same test suite, one Dockerfile template per package-manager family,
parametrized by `E2ELAB_BASE_IMAGE`. Every template installs providers via
`protean-installer.sh`'s own `install_wireguard`/`install_openvpn`/
`install_ikev2`/`install_xray` functions (see `dockerfiles/install-all.sh`)
— the real per-distro install logic, not a hand-copied package list — so
this genuinely validates `internal/hostboot/installer.sh` rather than a
parallel list that could silently drift from it.

| Family | Template | Verified live locally against |
|---|---|---|
| apt | `dockerfiles/apt.Dockerfile` | Debian 12 |
| dnf | `dockerfiles/dnf.Dockerfile` | Rocky Linux 9 |
| zypper | `dockerfiles/zypper.Dockerfile` | openSUSE Leap 15.6 |
| pacman | `dockerfiles/pacman.Dockerfile` | Arch Linux |
| apt-rpm hybrid | `dockerfiles/altlinux.Dockerfile` | ALT Linux — attempted live, genuinely doesn't work yet (see below) |

The CI `e2e-lab` job (nightly + manual only) runs the same suite across
every Hetzner/Timeweb catalog image researched for this pass — one
representative per family isn't the CI bar, every version is:

| Family | Images |
|---|---|
| apt | `ubuntu:18.04`\*, `ubuntu:20.04`\*, `ubuntu:22.04`, `ubuntu:24.04`, `ubuntu:26.04`, `debian:11`, `debian:12`, `debian:13` |
| dnf | `centos:stream9`, `centos:stream10`, `rockylinux:8`, `rockylinux:9`, `rockylinux:10`, `almalinux:8`, `almalinux:9`, `almalinux:10`, `fedora:43`, `fedora:44` |
| zypper | `opensuse/leap:15.6`, `opensuse/leap:16` |
| pacman | `archlinux:latest` |
| apt-rpm hybrid | `alt:p10` (best-effort, see above) |

\*18.04/20.04 are EOL upstream / deprecated by Hetzner — run best-effort
(`continue-on-error` in CI) for existing-fleet coverage, not as a target
for new deployments.

**Astra Linux 2.12** (Timeweb-only) has no publicly available Docker base
image and isn't covered by this automated harness — reported here rather
than silently dropped.

All four non-experimental families pass the full suite
(OpenVPN/IKEv2/Xray/IPForward/SSHFailureHandling). Getting there surfaced
five real, previously-undiscovered bugs — fixed in `scripts/protean-installer.sh`
(kept byte-identical to `internal/hostboot/installer.sh`, which is what
actually reaches a real host — see that file's header) unless noted
otherwise:

1. **RHEL-clones have no `ipsec.service` alias.** Debian/Ubuntu's
   strongswan package declares `Alias=ipsec.service` natively; RHEL-family's
   doesn't ship any unit named `ipsec` at all (`strongswan.service`/
   `strongswan-starter.service` only). `EnsureServer`'s
   `installer.Service(ctx, "enable", "ipsec")` failed outright on Rocky
   Linux 9 — IKEv2 would have been completely non-functional on any real
   Rocky/Alma/CentOS/Fedora deployment. Fixed via `ensure_ipsec_alias()` +
   an alias-aware `cmd_service` "enable" branch.
2. **RHEL-clones need EPEL for OpenVPN.** `dnf install openvpn easy-rsa`
   fails with "No match for argument" on a stock Rocky 9 — Fedora itself
   carries these natively, but RHEL-clones need `epel-release` enabled
   first. Fixed in `install_openvpn()`.
3. **Xray's `User=nobody` can never read its own config.** The official
   Xray installer's unit runs as `nobody`, but the panel's own bootstrap
   locks `/usr/local/etc/xray` to `750 protean:protean` (it holds
   plaintext client UUIDs/Reality keys, so — unlike the other conf dirs —
   it's deliberately not world-readable). `nobody` can't even traverse a
   750 directory it's not in the group for: xray.service failed to start
   on **every** distro tried, not just one. A test-harness timing quirk
   (systemd's `Restart=on-failure` briefly reporting a stale "active"
   status right after a crashed restart attempt) had been masking this as
   a pass in earlier, narrower runs. Fixed by overriding the unit to run
   as `protean` instead (a drop-in in `install_xray()`) — reuses the
   existing trust boundary (protean already manages every VPN config on
   the host) rather than loosening the directory to world-readable.
4. **A stray `"encryption": "none"` breaks VLESS on current Xray-core.**
   Xray 26.x rejects that key inside inbound `settings.clients` ("VLESS
   clients: \"encryption\" should not be in inbound settings") — it's only
   valid on the outbound/client-link side. This is a real product bug in
   `internal/vpn/xray/strategies.go`'s `VlessClients` (not the installer
   script) — every VLESS inbound the panel ever generated against a
   current Xray build would have failed to start. Fixed by dropping the
   key from the inbound client entries.
5. **openSUSE's OpenVPN package uses a different unit template and path
   convention entirely.** Debian/RHEL/Arch all ship `openvpn-server@.service`
   with `WorkingDirectory=/etc/openvpn/server` (config at
   `/etc/openvpn/server/<name>.conf`) — the convention hardcoded across
   `internal/vpn/openvpn` and `internal/servers/manager.go`. openSUSE ships
   only `openvpn@.service`, resolving to the flat path
   `/etc/openvpn/<name>.conf` instead. A plain unit alias would've just
   moved the same path mismatch one level down, so `ensure_openvpn_alias()`
   instead writes a real `openvpn-server@.service` unit using the
   Debian-style convention wherever the native template doesn't already
   provide one. Also needed: openSUSE has no `nobody` system user in its
   base image at all (Xray's installer hard-requires one to exist) —
   fixed by installing the `system-user-nobody` package first when
   missing; and `zypper install` returns a distinct, non-fatal exit code
   (107, `ZYPPER_EXIT_INF_RPM_SCRIPT_FAILED`) when an rpm `%post`
   scriptlet calls `systemctl` with no live systemd bus during a container
   build — `pkg_install`'s zypper branch now tolerates it.

### ALT Linux: attempted live, genuinely doesn't work yet

Unlike the four families above, ALT was actually run rather than assumed
to fail. Three test-harness-only fixes got it as far as booting and
provisioning the `protean` account:

- No `/sbin/init` compat symlink — only the real binary at
  `/lib/systemd/systemd` exists. Fixed by changing the Dockerfile's `CMD`.
- `sudo` refuses to run at all if **any** file under `/etc/sudoers.d/`
  fails its strict `0400`-mode check — the base image's own
  `99-sudopw` ships at `0500`, which alone blocked sudo for every user,
  independent of `ci-bootstrap`'s own sudoers rule being correct. Fixed
  by chmod'ing the whole directory to `0400` in the Dockerfile.
- `/usr/bin/sudo` itself is `4750 root:wheel` on ALT — not
  world-executable like the other four families — so `ci-bootstrap`
  couldn't even exec it without group membership. Fixed by adding
  `-G wheel` to its `useradd`.

With all three fixed, bootstrap itself succeeds (creating the `protean`
service account) — but then **every provider test fails identically**:
`sudo /usr/local/lib/protean/protean-installer.sh ...` as the `protean`
user hits the exact same "Permission denied" as `ci-bootstrap` did,
because `protean` is created by the panel's own (distro-agnostic)
bootstrap provisioning code, which doesn't know about ALT's wheel-gated
sudo model and doesn't add it to that group. Fixing that is real product
work (an `OS_FAMILY` case in `detect_os` plus wheel-awareness in
provisioning) that this pass didn't attempt — `TestE2ELabSSHFailureHandling`
(the one test needing no sudo) is the only one that passes; the other
four fail on this one root cause. Reported here precisely rather than as
a vague "doesn't work."

Two additional container-environment-only fixes (test harness, not the
product — wouldn't affect a real host):
- Arch's `systemd-networkd-wait-online.service` is enabled by default and
  spins until its own timeout since networkd never manages Docker's
  externally-configured veth — masked in `pacman.Dockerfile` alongside the
  other inapplicable-in-a-container units.
- `install-all.sh` now disables Xray after installing it, since the
  official installer auto-enables the unit at image *build* time —
  before the `protean` account exists (that only happens later, over SSH,
  at container *runtime*). Left enabled, xray would autostart at boot,
  crash on the missing user, and hit systemd's start-limit lockout before
  bootstrap ever got a chance to create that account — a race that can't
  happen for real (a real host's "install provider" is always a
  post-bootstrap admin action).

## Load test (`test/e2elab/loadtest`)

A separate, heavier harness (`//go:build e2eload`, `PROTEAN_E2ELOAD=1`) —
real client tunnels against a real server, at 1/10/50 concurrent peers,
with real traffic and CPU%/RSS sampling. See
`docs/SYSTEM-REQUIREMENTS.md` for the resulting sizing numbers and their
honesty caveats.

```sh
PROTEAN_E2ELOAD=1 go test -tags e2eload ./test/e2elab/loadtest/... -v -timeout 20m
```

Two containers this time — `protean-loadtest-server` (same distro-matrix
image family as e2elab, apt/Debian by default) and
`protean-loadtest-client` (new: `wg-tools`/`openvpn`/`strongswan-swanctl`/
`xray-core`/`iperf3`/`curl`), both attached to a dedicated docker network
(`protean-loadtest-net`) so they reach each other by real container IP —
no port-mapping juggling across four different protocols' worth of ports.

Each simulated peer for WireGuard/OpenVPN/Xray gets its own network
namespace inside the client container (veth pair back to the container's
root netns + NAT), mirroring `internal/vpn/wgfamily/integration_test.go`'s
own netns-per-instance precedent, just for the client role. **IKEv2 is
the one exception**: a single shared `charon` daemon runs N concurrent
real IKE_SAs (each with its own certificate), rather than N separate
per-netns daemons — strongSwan natively supports many simultaneous
connections from one instance (exactly like a real machine running
several IPsec profiles at once), and what matters for load-testing the
*server* is N genuine concurrent SAs with real ESP traffic, which a
single daemon delivers identically. `E2ELOAD_TIERS` (comma-separated,
default `1,10,50`) and `E2ELOAD_KEEP_CONTAINERS=1` (skip teardown for
post-mortem `docker exec`/`journalctl`) both work the same way as their
e2elab counterparts.

Building and debugging this surfaced three more real, previously-unknown
bugs (beyond the five from the distro matrix above), all fixed:

1. **Xray's inbound VLESS `"encryption": "none"` broke on current
   Xray-core.** Same root cause as one of the distro-matrix findings
   above (`internal/vpn/xray/strategies.go`'s `VlessClients`) — every
   VLESS inbound the panel generates would fail to start against a
   current Xray build. Already fixed there; the load test is what
   actually exercises a live client connecting through it end-to-end.
2. **IKEv2 server certs are unusable when `ServerID` is a bare IP.**
   `internal/vpn/ikev2/provider.go`'s `EnsureServer` always put `ServerID`
   into the certificate's DNS-name SANs, never its IP-address SANs, even
   when it's a plain IP (the common case for a VPS with no domain
   configured). strongSwan (and likely other strict IKEv2 clients)
   auto-types a dotted-quad `remote.id` as an IP-address identity and
   refused to trust a cert whose SAN only carried that IP as a DNS-type
   entry — "no trusted RSA public key found for '<ip>'", confirmed live
   against a real client trying to connect. Any real IKEv2 deployment
   sized by IP address alone would have hit this. Fixed by classifying
   `ServerID` via `net.ParseIP` and routing it to the correct SAN bucket.
3. Two narrower fixes needed only to build a correct *test* client for
   Xray, not the product: current Xray-core removed client-side
   `allowInsecure` (migrated to `pinnedPeerCertSha256`, a plain hex
   string, confirmed by reading the actual field name out of the
   `xray` binary since the docs error message alone didn't give the
   exact JSON shape); and a self-signed test cert needs a real
   `subjectAltName`, not just a CN, since Go's TLS stack (what Xray-core
   itself uses) has rejected CN-only certs since Go 1.15.

## Files

- `loadtest/client.Dockerfile` — the client container image (`wg-tools`,
  `openvpn`, `strongswan-swanctl`, `xray-core` fetched directly from
  GitHub releases since Xray's own installer refuses to run on a
  non-systemd host, `iperf3`, `curl`).
- `loadtest/loadtest_test.go` — shared harness: image builds, the two
  containers + dedicated network, bootstrap, per-tier result recording
  (`results.json` next to the test file), the generic `iperf3`-based
  tier runner.
- `loadtest/{wireguard,openvpn,ikev2,xray}_test.go` — one file per
  protocol: server setup (the same provider code test/e2elab's own
  `lab_test.go` uses) + real client bring-up + traffic generation.
- `dockerfiles/{apt,dnf,zypper,pacman,altlinux}.Dockerfile` — one test host
  image template per package-manager family (systemd + sshd + wg-tools +
  OpenVPN + strongSwan + xray-core, installed via the real
  `protean-installer.sh` install functions), parametrized by `ARG BASE_IMAGE`.
- `dockerfiles/install-all.sh` — sources `protean-installer.sh`'s function
  definitions (skipping its trailing CLI dispatch) and calls the install
  functions directly, sidestepping the one CLI precondition
  (`HAS_SYSTEMD`) that's a false negative during `docker build` (systemd
  isn't PID 1 yet at build time, only at real runtime).
- `testkey`/`testkey.pub` — a fixed, committed, test-only ed25519 keypair
  (zero real-world value: it only ever authenticates into a throwaway
  container destroyed at the end of every run). Baked into the image's
  `ci-bootstrap` user; also used, after bootstrap, to reach the `protean`
  service account the lab itself creates.
- `lab_test.go` (`//go:build e2elab`) — the actual tests.
- `doc.go` — untagged, keeps this directory buildable for the normal
  `go build`/`go vet`/`go test ./...` (no tag) even though the real test
  file is tag-gated.
