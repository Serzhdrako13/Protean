-- Per-server VPN instance registry, replacing the old "same fixed set of
-- interfaces on every server" bootstrap (env-var Template in
-- internal/servers/manager.go). Each row is one provider instance
-- (wireguard/amneziawg/openvpn/ikev2/xray) on one server; local_name is the
-- instance's interface/connection name (e.g. "wg0"), matching the existing
-- "<server_id>:<local_name>" registry key convention. config holds
-- type-specific settings (listen port, DNS pool, etc.) — wireguard/
-- amneziawg need none (conf path is derived from local_name by convention).
-- config is a JSON-encoded string (not jsonb) -- scanned as plain text and
-- decoded in Go, no pgx JSONB-specific handling needed.
CREATE TABLE IF NOT EXISTS protean.server_instances (
    server_id  text        NOT NULL REFERENCES protean.servers(id) ON DELETE CASCADE,
    local_name text        NOT NULL,
    type       text        NOT NULL,
    config     text        NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, local_name)
);
