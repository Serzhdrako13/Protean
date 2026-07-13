-- Certificate revocation (CRL) support for cert-based providers (OpenVPN,
-- IKEv2). revoked_certs records each revoked leaf by serial; crl_number keeps
-- the monotonic CRL sequence number per provider.
CREATE TABLE IF NOT EXISTS wgpanel.revoked_certs (
    provider   text        NOT NULL,
    serial     text        NOT NULL, -- decimal string of the cert serial (big.Int)
    cn         text        NOT NULL DEFAULT '',
    revoked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, serial)
);

CREATE TABLE IF NOT EXISTS wgpanel.crl_number (
    provider text   PRIMARY KEY,
    number   bigint NOT NULL DEFAULT 0
);
