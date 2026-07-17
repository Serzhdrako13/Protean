-- IKEv2 clients: issued cert (public) + AES-encrypted key, the PKCS#12 export
-- password (so the same .p12 can be re-downloaded), and routing metadata.
CREATE TABLE protean.ikev2_clients (
    cn           TEXT PRIMARY KEY,
    cert_pem     TEXT NOT NULL,
    enc_key_pem  BYTEA NOT NULL,
    p12_password TEXT NOT NULL DEFAULT '',
    address      TEXT NOT NULL DEFAULT '',
    subnets      TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
