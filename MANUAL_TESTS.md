# Manual tests (by hand, by user)

Running checklist of things Claude built/changed that need hands-on
verification by the user — accumulated across sessions, checked off in one
batch whenever the user gets to it. Not automated tests (see TESTING.md for
those) — this is specifically for things that need a human clicking
through a UI or using real infra Claude doesn't have credentials for.

- [ ] **Auth Methods settings page** (`/auth-methods` in the admin SPA) —
  browser click-through: Internal/LDAP/OIDC toggle cards render correctly,
  "Проверить подключение" buttons work from the UI (not just via curl),
  group-rule add/delete works through the table UI, save persists and
  reloads correctly.
- [x] **SSH bootstrap, positive path** (server create modal → "Настроить
  автоматически" tab) — done 2026-07-16: user re-added test-dn/test2
  through the UI with real sudo credentials (needed anyway — both hosts
  predated the project's rebrand and had stale pre-rebrand sudoers/installer
  paths). `protean` service account + new sudoers/installer confirmed live.
- [ ] **Dashboard compact/tile mode, card heights** (`/` → compact density →
  tile view) — with at least 2 servers side by side where one has more
  providers than the other: confirm both cards in a row now match height
  (was uneven before), items/gauges pinned to the top, traffic graph pinned
  to the bottom of each card.
- [ ] **CA import card + "Import existing certificate"** (provider page →
  Settings tab → Certificate authority card; and Overview tab → client
  table, for OpenVPN/IKEv2 providers) — browser click-through: CA status
  badge (internal/external + issued date) renders correctly, the
  cert/key/CRL textareas and validation work from the UI, "Import existing
  certificate" modal next to "Add client" opens/submits correctly. Backend
  fully verified live via curl this session (2026-07-16, against
  test-dn:ikev2/test-dn:server: external EC CA + CRL import, valid/revoked/
  impostor client-cert import) — only the actual form rendering/AntD
  interaction is unverified.
- [ ] **"Set up" overwrite-warning modal** (Servers → a server's providers
  list → per-row "Настроить"/Set up button, for a provider where
  `service_active`/`config_exists` is true) — browser click-through: the
  warning modal fires before re-provisioning, description/hint text reads
  correctly, "Открыть страницу провайдера" link navigates there, "Всё
  равно заменить" proceeds. Backend detect fields confirmed live
  (test-dn:ikev2 correctly flagged service_active=true/config_exists=true;
  test-dn:server flagged config_exists=true/installed=false) — only the
  modal itself is unverified.
- [ ] **test-dn cleanup: stale root-owned VPN config files** — found
  2026-07-16 while live-testing CA/CRL import and (later the same day) Xray
  modules: `/etc/openvpn/server/crl.pem`, `/etc/swanctl/x509crl/crl.pem`,
  `/etc/wireguard/wg0.conf`, and `/usr/local/etc/xray/config.json` on
  test-dn are owned by root (not `protean`), left over from before this
  host's `protean` service account existed (the re-added test-dn also logs
  `reconcile: list peers failed ... /etc/wireguard/wg0.conf: Permission
  denied` on panel startup for the same reason). `protean` owns the parent
  dirs but can't overwrite those files in place (`cat >` needs write on the
  file itself, not just the directory) — CRL rebuilds, wg0's peer list
  refresh, and Xray `Apply` all keep soft-failing with "... Permission
  denied" until they're `chown protean:protean`'d (or removed so the panel
  recreates them) by someone with real root on that box. Not a code bug —
  this panel's ImportCA/RebuildCRL/ImportPeer paths (CA/CRL feature) and the
  Xray file-module Apply path were otherwise all confirmed working
  correctly against this exact host (the generated Xray config.json was
  inspected in the error message and was fully correct JSON).
  Also note: `test-dn:xray`'s DB row is left configured with a test
  strategy (`e2e-ws-camouflage`) from that live test — harmless (a real
  strategy just needs re-applying once the config.json permission is
  fixed), but worth knowing it's there.
