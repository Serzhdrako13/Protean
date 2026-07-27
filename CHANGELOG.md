# Changelog

All notable changes to Protean are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions before 1.0 don't
promise a stable API/schema between releases.

## [0.3.2-alpha] - 2026-07-26

### Fixed
- Network group tags (Обзор сети: interfaces table + subnets card) had
  no icon at all -- added a `ClusterOutlined` icon, matching the same
  convention already used for equipment Kind icons.

## [0.3.1-alpha] - 2026-07-26

### Added
- Named network groups: a plain, admin-visible name (e.g. "Сеть 1")
  for a set of provider instances + subnets unified into one routable
  network, so a bare on/off status doesn't leave it ambiguous which
  network something belongs to when there are several. Auto-named
  during network structure detection (first subnet on an instance
  mints the name, later ones on the same instance reuse it silently);
  reconciled when two instances become mesh-linked (share/adopt a
  group, or -- if both already differently grouped -- left untouched
  with a warning rather than an automatic surprise merge). Manual
  picker (existing group / no group / type a new name) on the Subnets
  page and a provider's own mesh settings.

## [0.3.0-alpha] - 2026-07-26

### Added
- Per-subnet NAT mode for unifying router-fronted site subnets into one
  routable network: choose, per catalogued subnet, whether the VPN
  server masquerades its outbound-to-mesh traffic ("masquerade" -- the
  far router never needs a route back for the true source) or leaves
  it untouched ("passthrough", the default -- both routers need their
  own manual reciprocal route, which is the operator's own
  responsibility since Protean can never push config to a hand-adopted
  router's own device). Subnets page now shows which equipment fronts
  each subnet and a NAT toggle with the tradeoff explained inline.

## [0.2.5-alpha] - 2026-07-26

### Fixed
- Enabling mesh through network detection's apply flow only flipped
  the `MeshEnabled` DB flag -- it never re-provisioned a cert-based
  (OpenVPN/IKEv2) sibling's routes/FORWARD rules or re-checked
  `ip_forward`, unlike the manual mesh toggle on a provider's own
  settings page. Detection-enabled mesh now hot-applies the same way.

## [0.2.4-alpha] - 2026-07-26

### Fixed
- Network structure detection: a peer that already became equipment
  (a Node) before a second mesh-capable provider existed on the same
  server had no way to pick up the newly-relevant mesh pairing or
  subnet afterward -- applying was gated entirely on the peer not
  already being owned. Subnet/mesh application is now decoupled from
  node creation: an already-owned peer can keep gaining subnets/mesh
  through the same review flow, surfaced in the "already handled"
  section instead of requiring a manual reconfiguration.

## [0.2.3-alpha] - 2026-07-26

### Fixed
- Network structure detection couldn't turn an unnamed peer into
  equipment: a hand-written conf almost never has `# Name:` comments,
  so a real router-with-subnet peer classified as "anomaly" rather
  than "create equipment", and the review modal only offered a dismiss
  action for anomaly rows -- clicking "include" on one silently
  dismissed it instead of creating anything. Anomaly rows with a
  routed subnet now get the same editable name/kind/subnet/mesh form
  as a detected router, and applying without a name is rejected with a
  clear error instead of doing nothing. Added an "undismiss" action +
  button so a peer dismissed by the old broken flow isn't stuck hidden.
- `scripts/deploy.sh`: `-a` alone wasn't recursing into directory
  entries read from `--files-from` on this rsync build (dry-run showed
  "total size is 0" for `internal/`/`cmd/`) -- added an explicit `-r`.

## [0.2.2-alpha] - 2026-07-26

### Added
- Network structure detection for an adopted (pre-existing) WireGuard/
  AmneziaWG config: classifies each peer's `AllowedIPs` against the
  interface's own tunnel network to tell a plain client apart from a
  router/server fronting a real site subnet, and surfaces a reviewable
  "Обнаружить структуру сети" action (Оборудование tab) that -- only on
  explicit admin approval -- creates the matching Node, catalogues its
  routed subnet(s), and enables mesh with a sibling instance that
  already covers the same tunnel network. Never touches the adopted
  config file or the live interface; fully idempotent on repeat runs.
- Each VPN client's own address is now shown without its `/32`/`/128`
  host mask wherever it appears, and is never joined together with its
  routed site subnets in the same string.
- `scripts/deploy.sh`/`scripts/rollback.sh`: an explicit allow-list
  based deploy flow (dry-run by default, config/secrets backup before
  any apply, restarts only the target service) for pushing code to an
  already-running host without risking `.env`/secrets/data.

## [0.2.1-alpha] - 2026-07-25

### Added
- An "Адрес"/Address column showing each client's actual VPN-subnet
  address (`AllowedIPs`) in the two places that lacked it entirely: a
  provider's own peer table (`ProviderDetailPage`, which only had
  `Endpoint` -- the external IP:port a client happened to connect from
  last, useless for telling clients apart behind a shared NAT/ISP) and
  the "Все клиенты" tab (`NodesPage`'s `AllClientsTab`, which had no
  address column at all).

## [0.2.0-alpha] - 2026-07-25

### Added
- Web-based interactive SSH console for managed servers.
- OS updates check/apply, streamed live over the SSH console's WebSocket bridge.
- Firewall management with an armed-rollback safety net (a change that isn't
  confirmed within a timeout reverts itself, so a bad rule can't lock an
  admin out).
- SECRET_KEY rotation command.
- Xray file-based strategy modules, CA import/CRL improvements, IKEv2 CSR import.
- Multi-distro compatibility matrix (6 distro families incl. Astra Linux and
  ALT Linux), a real 4-protocol load test, and a sizing/system-requirements doc.
- GitHub Actions CI.
- A per-client "Клиенты" tab on the dashboard: every real connection
  (WireGuard/AmneziaWG/OpenVPN/IKEv2, Xray merged in by name) grouped into
  one row per real client, with per-provider colored abbreviations, a
  compact/expanded toggle, and per-row expand for connection detail.
- `GET /api/version` and a version line on the Help page.
- This CHANGELOG.

### Changed
- Finished the `wgpanel` → `protean` rename across the DB schema, docs,
  config, and remaining code (no `wgpanel` left anywhere).
- Admin SPA routes are now lazy-loaded (smaller initial bundle).
- `go test` no longer needs a real frontend build first.
- README wording/technical-accuracy fixes and stale page-name corrections (RU+EN).

### Fixed
- Two real distro-agnostic bugs surfaced by adding Astra Linux e2e-lab support.
- `servers.Manager` was auto-seeding the legacy provider Template for *any*
  newly-added server, not just the one legitimate case (the literal
  `"default"` server on a pre-multi-server upgrade).
- The dashboard's `Providers` field on a server could serialize as JSON
  `null` (nil slice) instead of `[]`, crashing the frontend's `.reduce`/`.filter`.
- IKEv2: `ListPeers` compared a raw `CN=<name>` identity against the bare
  stored CN and never matched, so no IKEv2 client ever showed as online.
- IKEv2 and OpenVPN: neither surfaced a client's real, dynamically-assigned
  tunnel address (only a pre-configured static one, if any).
- `protean-installer.sh`'s AmneziaWG install now pins to Ubuntu 24.04
  (noble) when the host's own codename has no PPA build yet, and cleans up
  the apt source it added on failure instead of leaving it to break every
  subsequent install.
- Dashboard: unnamed peers (adopted from a hand-written config predating
  Protean, so no `# Name:` comment) were wrongly merged into a single row
  regardless of being different real devices.
- Dashboard: the incoming/outgoing traffic gauge's text could overflow its ring.
- LDAP TLS verification being disabled now gets its own distinct audit entry.
- `console.Bridge.Run` returned as soon as the first of its 3 background
  goroutines finished, leaving the other two still running -- caught as a
  data race by CI's `go test -race` (this release's own CI, added above,
  catching a real pre-existing bug the very first time it ran).
- CI's `docker-smoke` job's teardown step was missing `--env-file
  .env.standalone`, so it failed on every single run trying to tear down
  the stack it had just built.

## [0.1.0-alpha] - 2026-07-13

Initial alpha release. Highlights: full SPA rewrite (React + Ant Design)
replacing the legacy server-rendered templates; backend
+ frontend i18n (RU/EN); the panel's own HTTPS (self-signed/ACME/manual/proxy);
progressive login brute-force protection with IP allow/deny lists; the
Protean rebrand; self-service portal enrichment (2FA, history, traffic,
protocol badges); and the core multi-server, multi-provider
(WireGuard/AmneziaWG/OpenVPN/IKEv2/Xray) management model.
