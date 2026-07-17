-- Multi-server scoping: every provider-keyed row moves from a bare instance
-- name (e.g. "wg0", "openvpn") to a server-scoped key "server:instance". A
-- single-server upgrade lands everything under the "default" server (the Go
-- startup seed creates that server row from the legacy SSH_* env).

-- Cert client tables were keyed by CN alone; add a provider scope so different
-- servers' clients can't collide, and re-key the primary key.
ALTER TABLE protean.openvpn_clients ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'default:openvpn';
ALTER TABLE protean.openvpn_clients ALTER COLUMN provider DROP DEFAULT;
ALTER TABLE protean.openvpn_clients DROP CONSTRAINT IF EXISTS openvpn_clients_pkey;
ALTER TABLE protean.openvpn_clients ADD PRIMARY KEY (provider, cn);

ALTER TABLE protean.ikev2_clients ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'default:ikev2';
ALTER TABLE protean.ikev2_clients ALTER COLUMN provider DROP DEFAULT;
ALTER TABLE protean.ikev2_clients DROP CONSTRAINT IF EXISTS ikev2_clients_pkey;
ALTER TABLE protean.ikev2_clients ADD PRIMARY KEY (provider, cn);

-- Prefix existing provider-keyed rows with the default server. Guarded by
-- NOT LIKE '%:%' so no-op if already scoped (idempotent, safe re-run).
UPDATE protean.peer_secrets       SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.peer_expiry        SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.disabled_peers     SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.peer_category      SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.notify_peer_mute   SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.ca_material        SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.revoked_certs      SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.crl_number         SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.cert_server_routes SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.conf_backups       SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
UPDATE protean.provider_settings  SET provider = 'default:' || provider WHERE provider NOT LIKE '%:%';
