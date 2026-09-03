-- Per-peer FORWARD destination allowlist: when a peer has >=1 row here,
-- the server restricts what that peer can reach THROUGH it (FORWARD
-- chain) to exactly these destinations. Zero rows = fully unrestricted
-- (today's exact behavior, unchanged for every existing setup). Mirrors
-- node_peer's (provider, peer_key) shape (migration 0036) -- peer_key is
-- the encoded urlID, the modern per-peer keying convention -- rather than
-- peer_category's legacy raw-pubkey keying.
CREATE TABLE protean.peer_forward_rules (
    provider    TEXT        NOT NULL,
    peer_key    TEXT        NOT NULL,
    destination TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, peer_key, destination)
);

CREATE INDEX peer_forward_rules_peer_idx ON protean.peer_forward_rules (provider, peer_key);
