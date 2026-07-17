-- Multi-server support: each row is a remote host the panel manages over SSH.
-- SSH private key is stored encrypted (AES, same Encryptor as peer secrets).
-- host_key pins the server's SSH host key (authorized_keys line); empty = TOFU.
CREATE TABLE IF NOT EXISTS protean.servers (
    id          text        PRIMARY KEY,          -- slug, used in URLs + as the DB scope prefix
    label       text        NOT NULL DEFAULT '',
    host        text        NOT NULL,
    port        integer     NOT NULL DEFAULT 22,
    ssh_user    text        NOT NULL,
    enc_key_pem bytea       NOT NULL,             -- AES-sealed SSH private key PEM
    host_key    text        NOT NULL DEFAULT '',  -- pinned host public key (authorized_keys line)
    public_host text        NOT NULL DEFAULT '',  -- endpoint advertised to clients (defaults to host)
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
