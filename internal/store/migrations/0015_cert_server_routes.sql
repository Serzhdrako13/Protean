-- Persist the push-routes / egress last applied to a cert-based server, so the
-- provider can regenerate its config (e.g. IKEv2 per-client site connections)
-- on a plain peer add/update/remove without the API recomputing mesh routes.
CREATE TABLE IF NOT EXISTS protean.cert_server_routes (
    provider    text        PRIMARY KEY,
    push_routes text        NOT NULL DEFAULT '', -- comma-separated CIDRs
    egress      boolean     NOT NULL DEFAULT false,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
