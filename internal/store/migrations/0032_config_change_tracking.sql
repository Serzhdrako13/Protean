-- Lets the portal tell a user their downloaded config is stale: when an
-- admin edits an instance's server-config (address/port/DNS/subnet/MTU),
-- config_changed_at is bumped; when a user actually downloads/QR-scans
-- their config, peer_owner.config_downloaded_at is bumped. The portal
-- flags an instance as stale when config_changed_at is newer than the
-- owning peer's config_downloaded_at (falling back to the grant time,
-- peer_owner.created_at, if the user never downloaded yet).
ALTER TABLE wgpanel.server_instances ADD COLUMN config_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE wgpanel.peer_owner ADD COLUMN config_downloaded_at TIMESTAMPTZ;
