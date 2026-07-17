-- Pre-write snapshots of each interface's config file. The panel cannot
-- create backup files in /etc/wireguard (it only has write access to the
-- conf file itself, not the directory), so backups live here instead. Lets
-- a clobbered config be recovered.
CREATE TABLE protean.conf_backups (
    id       BIGSERIAL PRIMARY KEY,
    provider TEXT NOT NULL,
    saved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    content  TEXT NOT NULL
);

CREATE INDEX conf_backups_provider_saved_idx ON protean.conf_backups (provider, saved_at DESC);
