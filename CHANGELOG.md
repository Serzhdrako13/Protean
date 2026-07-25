# Changelog

All notable changes to Protean are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions before 1.0 don't
promise a stable API/schema between releases.

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

## [0.1.0-alpha] - 2026-07-13

Initial alpha release. Highlights: full SPA rewrite (React + Ant Design,
3x-ui-modeled UI) replacing the legacy server-rendered templates; backend
+ frontend i18n (RU/EN); the panel's own HTTPS (self-signed/ACME/manual/proxy);
progressive login brute-force protection with IP allow/deny lists; the
Protean rebrand; self-service portal enrichment (2FA, history, traffic,
protocol badges); and the core multi-server, multi-provider
(WireGuard/AmneziaWG/OpenVPN/IKEv2/Xray) management model.
