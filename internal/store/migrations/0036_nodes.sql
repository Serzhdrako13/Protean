-- "Узлы и устройства" (nodes): a non-portal, non-login owner for
-- equipment peers (routers, external servers acting as VPN clients),
-- deliberately kept as its own table rather than widening peer_owner --
-- see the plan doc for why (peer_owner/access_request stay untouched,
-- zero risk to the existing portal-login ownership path).
CREATE TABLE wgpanel.nodes (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('router', 'device', 'other')),
    role        TEXT NOT NULL CHECK (role IN ('member', 'network_node')) DEFAULT 'member',
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Mirrors peer_owner's shape exactly (same provider/peer_key convention),
-- just FK'd to nodes instead of users.
CREATE TABLE wgpanel.node_peer (
    provider   TEXT        NOT NULL,
    peer_key   TEXT        NOT NULL,
    node_id    BIGINT      NOT NULL REFERENCES wgpanel.nodes(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, peer_key)
);

CREATE INDEX node_peer_node_id_idx ON wgpanel.node_peer(node_id);
