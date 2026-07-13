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
- [ ] **SSH bootstrap, positive path** (server create modal → "Настроить
  автоматически" tab) — root or an existing sudo user, real
  password/private key, against a real host: confirm the service account
  (`protean` by default) actually gets created/reused correctly end to end
  from the UI (not just via curl, which was already verified) — i.e. the
  full happy path with real root/sudo credentials Claude doesn't have.
- [ ] **Dashboard compact/tile mode, card heights** (`/` → compact density →
  tile view) — with at least 2 servers side by side where one has more
  providers than the other: confirm both cards in a row now match height
  (was uneven before), items/gauges pinned to the top, traffic graph pinned
  to the bottom of each card.
