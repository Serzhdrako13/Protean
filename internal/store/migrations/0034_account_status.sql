-- Two independent account-lifecycle states, distinct from full deletion:
-- enabled=false blocks ALL login (admin or portal) and is paired (in Go,
-- see internal/api/api_users.go) with revoking every VPN peer the account
-- owns -- "the account is disabled, its VPN providers stop working".
-- portal_access_enabled=false only blocks the self-service portal login
-- path (role='user' accounts) while leaving any existing VPN peers
-- running untouched -- a lighter control than disabling the account.
ALTER TABLE wgpanel.users ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE wgpanel.users ADD COLUMN portal_access_enabled BOOLEAN NOT NULL DEFAULT true;
