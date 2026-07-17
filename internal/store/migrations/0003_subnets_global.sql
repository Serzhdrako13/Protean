-- Subnets become a single mesh-wide catalog of routable site networks
-- rather than a per-provider list: with cross-provider routing, a subnet is
-- reachable regardless of which VPN transport a client uses. The provider
-- column is kept for backwards compatibility but no longer scopes anything.
ALTER TABLE protean.subnets ALTER COLUMN provider SET DEFAULT '';

ALTER TABLE protean.subnets DROP CONSTRAINT IF EXISTS subnets_provider_cidr_key;

-- A given network may only exist once in the mesh (overlap is checked in the
-- app layer; this catches exact duplicates at the DB level).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'subnets_cidr_key'
    ) THEN
        ALTER TABLE protean.subnets ADD CONSTRAINT subnets_cidr_key UNIQUE (cidr);
    END IF;
END$$;
