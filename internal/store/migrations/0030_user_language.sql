-- Per-account UI language preference (RU/EN toggle) -- previously only
-- persisted in the browser's localStorage, so it didn't follow a user
-- across devices/browsers and reset for portal users on every new machine.
-- Empty string = "no preference saved yet", frontend falls back to
-- browser/localStorage detection as before.
ALTER TABLE wgpanel.users ADD COLUMN language TEXT NOT NULL DEFAULT '';
