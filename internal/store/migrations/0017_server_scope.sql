-- Multi-server scoping: every provider-keyed row moves from a bare instance
-- name (e.g. "wg0", "openvpn") to a server-scoped key "server:instance". A
-- single-server upgrade lands everything under the "default" server (the Go
-- startup seed creates that server row from the legacy SSH_* env).

-- Cert client tables were keyed by CN alone; add a provider scope so different
-- servers' clients can't collide, and re-key the primary key.
ALTER TABLE wgpanel.openvpn_clients ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'default:openvpn';
ALTER TABLE wgpanel.openvpn_clients ALTER COLUMN provider DROP DEFAULT;
ALTER TABLE wgpanel.openvpn_clients DROP CONSTRAINT IF EXISTS openvpn_clients_pkey;
ALTER TABLE wgpanel.openvpn_clients ADD PRIMARY KEY (provider, cn);

ALTER TABLE wgpanel.ikev2_clients ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'default:ikev2';
ALTER TABLE wgpanel.ikev2_clients ALTER COLUMN provider DROP DEFAULT;
ALTER TABLE wgpanel.ikev2_clients DROP CONSTRAINT IF EXISTS ikev2_clients_pkey;
ALTER TABLE wgpanel.ikev2_clients ADD PRIMARY KEY (provider, cn);

-- Prefix existing provider-keyed rows with the default server. Guarded by
-- NOT LIKE '%:%' so no-op if already scoped (idempotent, safe re-run).
UPDATE wgpanel.peer_secrets       SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.peer_expiry        SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.disabled_peers     SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.peer_category      SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.notify_peer_mute   SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.ca_material        SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.revoked_certs      SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.crl_number         SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.cert_server_routes SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.conf_backups       SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE wgpanel.provider_settings  SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
