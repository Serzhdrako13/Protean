-- Peer category, so events can be selected per class of peer: "site"
-- (routers/servers, where a disconnect means a site is down) vs "client"
-- (roaming users, where a connect tells you who came online). Absent = client.
CREATE TABLE protean.peer_category (
    provider TEXT NOT NULL,
    peer_id  TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'client',
    PRIMARY KEY (provider, peer_id)
);

-- Per-category event selection + an "unknown/foreign peer connected" alert
-- (a connected peer with no panel record -- helps spot someone who wasn't
-- provisioned here). Replaces the single ev_peer_onoff toggle.
ALTER TABLE protean.notify_settings ADD COLUMN ev_site_connect      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE protean.notify_settings ADD COLUMN ev_site_disconnect   BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE protean.notify_settings ADD COLUMN ev_client_connect    BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE protean.notify_settings ADD COLUMN ev_client_disconnect BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE protean.notify_settings ADD COLUMN ev_unknown_peer      BOOLEAN NOT NULL DEFAULT true;
