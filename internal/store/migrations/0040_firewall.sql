-- Per-server INPUT-chain firewall management (highest-risk item in the
-- "firewall + OS updates + web SSH console" backlog -- see the design
-- notes: a bad rule can sever SSH/panel access to a node with no physical
-- recourse, so applying is always paired with a host-side armed rollback
-- timer, and only firewall-confirm (over a fresh, non-pooled SSH
-- connection) ever persists a change past that window).
--
-- Baseline "never lock these out" ports (SSH port, each VPN instance's
-- listening port, panel ports if the server is the panel host) are NOT
-- stored here -- they're recomputed from live DB/host state at every
-- apply so they can never drift stale into a lockout. Only the admin's
-- own custom rules and the last-applied rendered ruleset are persisted.
CREATE TABLE protean.firewall_policy (
    server_id            text        PRIMARY KEY REFERENCES protean.servers(id) ON DELETE CASCADE,
    enabled              boolean     NOT NULL DEFAULT false,
    default_incoming     text        NOT NULL DEFAULT 'drop' CHECK (default_incoming IN ('drop', 'accept')),
    rollback_window_secs integer     NOT NULL DEFAULT 300 CHECK (rollback_window_secs BETWEEN 30 AND 3600),
    last_applied_ruleset text        NOT NULL DEFAULT '',
    last_applied_at      timestamptz,
    last_confirmed_at    timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- The admin's own custom rules, evaluated in `ordering` after the
-- always-on baseline/loopback/established rules render() prepends.
CREATE TABLE protean.firewall_rules (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_id   text        NOT NULL REFERENCES protean.servers(id) ON DELETE CASCADE,
    ordering    integer     NOT NULL,
    action      text        NOT NULL CHECK (action IN ('accept', 'drop', 'reject')),
    proto       text        NOT NULL CHECK (proto IN ('tcp', 'udp', 'any')),
    port_spec   text        NOT NULL DEFAULT '', -- "443", "8000:8100", "80,443" -- empty = any port
    source_cidr text        NOT NULL DEFAULT '', -- empty = anywhere
    comment     text        NOT NULL DEFAULT '',
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX firewall_rules_server_id_ordering ON protean.firewall_rules (server_id, ordering);
