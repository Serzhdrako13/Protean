ALTER TABLE protean.server_instances ADD COLUMN label TEXT NOT NULL DEFAULT '';

-- A portal user's request for access to one provider instance. No peer
-- exists yet at request time -- that's why this is keyed by (user_id,
-- provider) rather than a peer id, unlike protean.peer_owner.
--
-- status: pending  = just requested, admin hasn't acted.
--         approved  = admin said yes, but there's no confirmed-working peer
--                     yet (cert-based providers always land here after
--                     approval; wg-family lands here only if
--                     auto-provisioning's post-creation check failed).
--         granted   = a real peer exists and passed the sanity check --
--                     the only status the portal renders as "available".
--         denied    = admin said no.
CREATE TABLE protean.access_request (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES protean.users(id) ON DELETE CASCADE,
    provider   TEXT        NOT NULL,
    status     TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'granted', 'denied')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, provider)
);
