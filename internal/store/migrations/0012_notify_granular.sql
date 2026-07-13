-- Fine-grained notification content: which fields to include in event
-- messages. Defaults keep the current concise messages.
ALTER TABLE wgpanel.notify_settings ADD COLUMN ctnt_provider BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE wgpanel.notify_settings ADD COLUMN ctnt_endpoint BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE wgpanel.notify_settings ADD COLUMN ctnt_address  BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE wgpanel.notify_settings ADD COLUMN ctnt_time     BOOLEAN NOT NULL DEFAULT false;

-- Per-peer notification mute: when the global peer-events toggle is on, peers
-- listed here are silenced (choose which connected clients notify).
CREATE TABLE wgpanel.notify_peer_mute (
    provider TEXT NOT NULL,
    peer_id  TEXT NOT NULL,
    PRIMARY KEY (provider, peer_id)
);
