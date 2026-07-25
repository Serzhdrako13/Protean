-- Remembers a peer an admin explicitly reviewed during network-structure
-- detection (see internal/api/network_detect.go) and declined to turn
-- into equipment -- e.g. a wide AllowedIPs entry that turned out to be a
-- fat-fingered mask, not a real routed site subnet. Without this, a
-- re-run of detection (new peers added to the hand-written conf
-- externally, or a manual re-check) would keep re-suggesting the same
-- already-dismissed peer every time.
--
-- Node ownership and the Subnets catalog need no equivalent table:
-- node_peer's own primary key and subnets.cidr's existing UNIQUE
-- constraint already make those two idempotent on their own. This is the
-- one genuinely new piece of state -- an explicit human decline, which
-- nothing else records.
CREATE TABLE protean.peer_detection_dismissed (
    provider     text        NOT NULL,
    peer_key     text        NOT NULL,
    dismissed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, peer_key)
);
