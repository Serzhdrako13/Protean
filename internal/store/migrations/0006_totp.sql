-- Optional per-user TOTP two-factor auth. Off by default; a user opts in from
-- the account page. totp_secret is the base32 shared secret (empty when
-- unused); totp_enabled gates whether login requires a code.
ALTER TABLE wgpanel.users ADD COLUMN totp_secret  TEXT    NOT NULL DEFAULT '';
ALTER TABLE wgpanel.users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT false;
