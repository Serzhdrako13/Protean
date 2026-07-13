-- Web UI TLS: how the panel's own HTTP(S) listener gets its certificate.
-- Singleton row (id enforced true) -- there is exactly one panel listener,
-- unlike server_instances/providers which are per-server.
--
-- mode:
--   self_signed -- panel's own internal CA issues+renews a leaf cert (default,
--                  auto-bootstrapped on first run so the panel is never
--                  reachable over plain HTTP even before an admin logs in).
--   acme        -- generic ACME client against a configurable directory URL
--                  (Let's Encrypt prod/staging, or a private ACME server such
--                  as step-ca -- not hardcoded to any one provider).
--   manual      -- admin pastes an externally-obtained cert+key (e.g. issued
--                  by certbot elsewhere, or when automated issuance isn't
--                  reachable from this host at all).
--   proxy       -- a reverse proxy (Traefik etc.) terminates TLS in front;
--                  the panel serves plain HTTP on its own internal listener
--                  (normal for that pattern) and trusts X-Forwarded-Proto.
CREATE TABLE wgpanel.tls_state (
    id                   boolean PRIMARY KEY DEFAULT true CHECK (id),
    mode                 text NOT NULL DEFAULT 'self_signed'
                         CHECK (mode IN ('self_signed', 'acme', 'manual', 'proxy')),

    -- self-signed settings
    ss_key_algo          text NOT NULL DEFAULT 'ecdsa_p256'
                         CHECK (ss_key_algo IN ('rsa_2048', 'rsa_4096', 'ecdsa_p256', 'ecdsa_p384')),
    ss_validity_days     int NOT NULL DEFAULT 397, -- matches the CA/Browser Forum's own public-cert cap
    ss_renew_before_days int NOT NULL DEFAULT 30,
    -- ss_sans: comma-separated hostnames/IPs the leaf cert should cover.
    -- Empty (first boot, before an admin has set anything) falls back to
    -- localhost/127.0.0.1/::1 -- enough for the panel to be reachable over
    -- HTTPS immediately, even though a browser will still flag it as
    -- untrusted (expected for a self-signed cert) until re-issued with the
    -- admin's real hostname/IP.
    ss_sans              text NOT NULL DEFAULT '',

    -- ACME settings
    acme_directory_url   text NOT NULL DEFAULT '', -- empty until admin picks a preset or types one
    acme_domains         text NOT NULL DEFAULT '', -- comma-separated
    acme_email           text NOT NULL DEFAULT '',
    acme_challenge       text NOT NULL DEFAULT 'tls-alpn-01'
                         CHECK (acme_challenge IN ('tls-alpn-01', 'http-01')),
    -- acme_trust_root_pem: extra CA root to trust for the ACME directory
    -- itself (a private ACME server like step-ca usually isn't signed by a
    -- publicly-trusted root) -- plaintext PEM, it's a public cert, nothing
    -- to seal.
    acme_trust_root_pem  text NOT NULL DEFAULT '',

    -- manual cert: PEM cert chain plaintext (public), key sealed at rest via
    -- the panel's existing Encryptor (same convention as every other
    -- private-key column in this schema).
    manual_cert_pem      text NOT NULL DEFAULT '',
    manual_key_enc       bytea,

    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- ACME account/cert cache (golang.org/x/crypto/acme/autocert.Cache shape:
-- opaque string key -> blob). Values are sealed via the panel's Encryptor --
-- this cache holds the ACME account private key and issued cert+key bundles.
CREATE TABLE wgpanel.acme_cache (
    key   text PRIMARY KEY,
    value bytea NOT NULL
);

-- Self-signed CA + current leaf cert material, kept separate from tls_state
-- so switching modes back and forth doesn't lose the self-signed identity
-- (it's also the permanent fallback -- see internal/webtls) and doesn't
-- force a new CA (new self-signed root) each time.
CREATE TABLE wgpanel.tls_self_signed (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    ca_cert_pem   text NOT NULL,
    ca_key_enc    bytea NOT NULL,
    leaf_cert_pem text NOT NULL DEFAULT '',
    leaf_key_enc  bytea,
    issued_at     timestamptz,
    expires_at    timestamptz
);
