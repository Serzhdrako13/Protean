# Zabbix templates for Protean

Ready-to-import templates that scrape the panel's `/metrics` endpoint.

- `protean-zabbix-7.4.yaml` — Zabbix 7.4
- `protean-zabbix-8.0.yaml` — Zabbix 8.0

The two files are identical except for the export `version` field; import the
one matching your Zabbix server.

## Prerequisites

- The panel is started with `METRICS_TOKEN` set (see `.env`); otherwise
  `/metrics` returns 404.
- Zabbix server/proxy can reach the panel URL (directly on the host, over the
  internal network, or via the HTTPS reverse proxy in front of it).

## Import

1. Zabbix UI → **Data collection → Templates → Import**, pick the YAML.
2. Create/pick a host (e.g. the VPS), link template **"Protean by HTTP"**.
3. On the host (or template) set macros:
   - `{$PROTEAN_URL}` — base URL, e.g. `http://127.0.0.1:8080` or
     `https://vpn.example.com` (no trailing slash).
   - `{$PROTEAN_TOKEN}` — the panel's `METRICS_TOKEN`.
   - `{$PROTEAN_INTERVAL}` — scrape interval (default `1m`).
   - `{$PROTEAN_PEER_HS_MAX}` — stale-handshake threshold in seconds
     (default `3600`).

## What you get

- **Master item** `protean.metrics` (HTTP agent) fetches the exposition; every
  other item is dependent on it (one scrape per interval).
- Per-provider (wireguard, amneziawg): interface up, peers total/online,
  rx/tx bytes.
- **Peer discovery (LLD)**: auto-creates online / last-handshake-age / rx / tx
  items per peer, plus a "peer offline" trigger.
- Triggers: WireGuard down (High), AmneziaWG down (Average), no metrics for
  10m (Warning).

If your host runs only one of the two VPNs, the items for the absent one just
stay "not supported"/no-data — harmless. Adjust or disable them if you prefer.
