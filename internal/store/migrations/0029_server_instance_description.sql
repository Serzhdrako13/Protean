-- Admin-settable freeform note per instance (e.g. "домашняя сеть, egress
-- запрещён" / "резервный медленный канал" / "обход блокировок, не входит во
-- внутреннюю сеть") -- shown to self-service portal users alongside the
-- friendly label, so they understand WHAT each connection is for, not just
-- its name.
ALTER TABLE wgpanel.server_instances ADD COLUMN description TEXT NOT NULL DEFAULT '';
