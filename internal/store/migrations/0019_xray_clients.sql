-- Clients (credentials) on an Xray instance. Multiple clients share one
-- instance's transport/strategy; each credential (uuid/password) is stored
-- AES-encrypted as a JSON blob.
CREATE TABLE IF NOT EXISTS protean.xray_clients (
    provider   text        NOT NULL,   -- server:instance key
    name       text        NOT NULL,
    enc_cred   bytea       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, name)
);
