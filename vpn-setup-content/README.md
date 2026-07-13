# Self-service portal: "how to connect" content

This directory is bind-mounted into the panel container at `/data/vpn-setup`
(see `docker-compose.yml`/`docker-compose.standalone.yml`). It's how the portal's
per-protocol connection instructions (which app to install, where to get it,
step-by-step setup per OS) get edited **without rebuilding or redeploying**
the panel — app names, download links, and install flows drift over time,
and a text edit + no restart needed should be enough to fix a stale one.

On first boot, the panel auto-seeds this directory with working `ru.json`
and `en.json` files (copied from its built-in defaults) if they don't exist
yet — it never overwrites a file that's already here, so your edits always
win on every subsequent restart.

## Format

One file per language: `ru.json`, `en.json`, and so on — add a new
`<lang>.json` here to support another portal UI language (matching
whatever language codes the frontend's i18n setup uses, e.g. `de` for
German). If a requested language's file is missing, the panel falls back to
its embedded English defaults, so a partial/missing translation never
breaks the modal.

Each file is a single JSON object keyed by provider type (`wireguard`,
`amneziawg`, `openvpn`, `ikev2`), each holding:

```json
{
  "wireguard": {
    "app": "WireGuard",
    "appUrl": "https://www.wireguard.com/install/",
    "appNote": "Free-text note shown next to the app name/link.",
    "windows": ["Step 1.", "Step 2.", "..."],
    "macos": ["..."],
    "linux_nm": ["..."],
    "linux_cli": ["..."],
    "ios": ["..."],
    "android": ["..."]
  }
}
```

- `app`/`appUrl`/`appNote` — shown once at the top of the "How to connect"
  modal, regardless of which OS tab is selected. `appUrl` may be empty
  (e.g. IKEv2, which has no single official client app) — then no link is
  shown.
- `windows`/`macos`/`linux_nm`/`linux_cli`/`ios`/`android` — each an array
  of short step strings, rendered as a numbered list. `linux_nm` and
  `linux_cli` are the two Linux sub-tabs (NetworkManager GUI vs. command
  line) shown only when the Linux OS tab is selected.
- Any `https://...` URL or bare `domain.tld` mention inside a step's text
  is automatically turned into a clickable link by the frontend — no HTML
  markup needed in the JSON itself.

Changes take effect immediately on the next request — no container restart
needed (the panel re-reads the file from disk every time, not cached).
