-- Soft-disabled peers. wg-quick has no "disabled" state -- a [Peer] block in
-- the config is always active -- so to disable a peer without losing it we
-- remove it from the live interface and config and stash its definition here.
-- Enabling re-adds it verbatim (same public key, routes, keepalive).
CREATE TABLE wgpanel.disabled_peers (
    provider    TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    allowed_ips TEXT NOT NULL DEFAULT '',  -- comma-separated
    keepalive   INT  NOT NULL DEFAULT 0,
    disabled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, public_key)
);
