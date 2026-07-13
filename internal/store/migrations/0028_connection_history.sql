-- Persisted connect/disconnect history -- previously only detected
-- transiently by internal/api/notify.go's watchTick (for live
-- notifications) and then discarded; this keeps a permanent, prunable log.
-- Same convention as traffic_samples (migration 0020): bigserial PK,
-- denormalized "server:instance" provider key (no FK), pruned by a raw
-- DELETE on a retention window rather than kept forever.
CREATE TABLE IF NOT EXISTS wgpanel.connection_history (
    id        bigserial   PRIMARY KEY,
    ts        timestamptz NOT NULL,
    provider  text        NOT NULL,
    peer_id   text        NOT NULL, -- wg-family/cert-based: public key/CN; matches vpn.Peer.PublicKey
    peer_name text        NOT NULL DEFAULT '',
    event     text        NOT NULL CHECK (event IN ('connect', 'disconnect'))
);
CREATE INDEX IF NOT EXISTS idx_connection_history_provider_ts
    ON wgpanel.connection_history (provider, ts);
CREATE INDEX IF NOT EXISTS idx_connection_history_peer_ts
    ON wgpanel.connection_history (peer_id, ts);
