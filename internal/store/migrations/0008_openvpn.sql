-- CA material for certificate-based providers (openvpn, ikev2). The private
-- key is AES-encrypted by the app (same scheme as peer_secrets); source is
-- 'internal' (panel-generated) or 'external' (BYOC / step-ca export).
CREATE TABLE protean.ca_material (
    provider     TEXT PRIMARY KEY,
    cert_pem     TEXT NOT NULL,
    enc_key_pem  BYTEA NOT NULL,
    source       TEXT NOT NULL DEFAULT 'internal',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- OpenVPN clients: the issued cert (public) + its AES-encrypted key, plus the
-- routing metadata needed to rebuild the client-config-dir entry and the
-- .ovpn bundle. The tunnel address and served subnets are the panel's record;
-- the live truth is the ccd file on the host.
CREATE TABLE protean.openvpn_clients (
    cn          TEXT PRIMARY KEY,
    cert_pem    TEXT NOT NULL,
    enc_key_pem BYTEA NOT NULL,
    address     TEXT NOT NULL DEFAULT '',   -- assigned tunnel IP (ifconfig-push)
    subnets     TEXT NOT NULL DEFAULT '',   -- comma-separated iroute site subnets
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
