# Xray strategy modules

This directory is bind-mounted into the panel container at
`/data/xray-modules` (see `docker-compose.yml`/`docker-compose.standalone.yml`).
It's how new Xray DPI-evasion strategies (transport + camouflage + client
type) get added **without rebuilding or redeploying** the panel — which
countermeasure actually works against a given ISP's blocking changes over
time, and a JSON file drop-in + no restart needed should be enough to react.

On first boot, the panel auto-seeds this directory with one annotated
example file (`_example.json.txt`) if it doesn't exist yet — it never
overwrites a file that's already here, so your modules always survive a
restart. That file is documentation, not a real module (it doesn't end in
`.json`, and filenames starting with `_` are skipped anyway) — copy its
JSON into a new `<name>.json` file here to actually add a strategy.

## Format

One file per strategy, named however you like (`.json` extension
required). See `_example.json.txt` for a fully annotated walkthrough of
every field; in short, each module declares:

- `name`/`label` — the strategy's stable slug and its display name in the
  Xray page's dropdown.
- `cred` — `"uuid"` or `"password"`, which credential kind each client gets.
- `client_format` — `"vless"`, `"vmess"`, or `"trojan"` (Shadowsocks-style
  single-instance-credential strategies aren't supported by modules yet).
- `multi_client` — whether more than one client can share the strategy.
- `params` — the fields an admin fills in when applying this strategy on
  the Xray page (port, camouflage domain, etc).
- `instance_secrets` — server-generated values never shown to the admin
  (e.g. a Reality keypair), generated once and reused on every re-apply.
- `inbound` — the actual Xray inbound object, with `"{{param_key}}"`
  placeholders substituted at build time (and a special `"{{clients}}"`
  token for the built client list).
- `client_link_template` — the share-link template, same `"{{token}}"`
  substitution.

A module whose `name` collides with one of the panel's built-in strategies
is rejected (logged as a warning, not applied) — a file can never shadow a
vetted built-in. A malformed file is skipped the same way, without
affecting any other module in this directory.

Changes take effect immediately on the next request — no container restart
needed (the panel re-reads this directory every time, not cached).
