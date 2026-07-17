-- Explicit opt-in: an instance is invisible to the self-service portal
-- until an admin marks it visible (default false), even if the user would
-- otherwise be able to request it. MTU needs no schema change -- it's a
-- config-file field (wg-quick/AmneziaWG interface), not panel-stored state.
ALTER TABLE protean.server_instances ADD COLUMN portal_visible BOOLEAN NOT NULL DEFAULT false;
