-- Optional per-peer expiry. When set and passed, a background worker disables
-- (wg-family) or removes (cert-based) the peer -- for temporary/guest access.
-- Keyed by provider INSTANCE id + peer id (public key or CN).
CREATE TABLE protean.peer_expiry (
    provider   TEXT NOT NULL,
    peer_id    TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (provider, peer_id)
);

CREATE INDEX peer_expiry_due_idx ON protean.peer_expiry (expires_at);
