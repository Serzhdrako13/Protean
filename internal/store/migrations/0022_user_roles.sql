ALTER TABLE wgpanel.users
    ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'user'));

-- Links an existing peer (its URLID, same identifier the panel already uses
-- for /peers/{id}/config|qr) to the portal user allowed to self-service it.
-- Peers themselves aren't stored in one place (wg-family lives on the host,
-- cert-based peers have their own tables) -- this is deliberately just a
-- thin ownership pointer, not a peers table of its own.
CREATE TABLE wgpanel.peer_owner (
    provider   TEXT        NOT NULL,
    peer_key   TEXT        NOT NULL,
    user_id    BIGINT      NOT NULL REFERENCES wgpanel.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, peer_key)
);

CREATE INDEX peer_owner_user_id_idx ON wgpanel.peer_owner(user_id);
