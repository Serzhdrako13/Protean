CREATE SCHEMA IF NOT EXISTS wgpanel;

CREATE TABLE wgpanel.users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE wgpanel.sessions (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES wgpanel.users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sessions_expires_at_idx ON wgpanel.sessions(expires_at);

-- Reference list of routable subnets ("доступные подсети") offered when
-- assigning AllowedIPs to a peer. Not the source of truth for what a peer
-- currently advertises -- that lives in the host's wg-quick config file.
CREATE TABLE wgpanel.subnets (
    id         BIGSERIAL PRIMARY KEY,
    provider   TEXT NOT NULL,
    cidr       CIDR NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, cidr)
);

-- Private keys for peers the panel generated itself, so client configs/QR
-- codes can be re-downloaded later. Encrypted at rest (AES-GCM, app-level
-- key from SECRET_KEY env var) -- this table is the only place secret key
-- material touches the database.
CREATE TABLE wgpanel.peer_secrets (
    provider               TEXT NOT NULL,
    public_key             TEXT NOT NULL,
    encrypted_private_key  BYTEA NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, public_key)
);
