-- Notification channels: per-kind enabled flag + AES-encrypted config JSON
-- (tokens/URLs/SMTP/XMPP creds). Encryption happens in the app layer.
CREATE TABLE protean.notify_channels (
    kind       TEXT PRIMARY KEY,
    enabled    BOOLEAN NOT NULL DEFAULT false,
    config     BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Singleton notification settings: which events fire instant channels, and
-- the accumulating email report (frequency + content).
CREATE TABLE protean.notify_settings (
    id                    BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    ev_iface_updown       BOOLEAN NOT NULL DEFAULT true,
    ev_peer_onoff         BOOLEAN NOT NULL DEFAULT false,
    report_enabled        BOOLEAN NOT NULL DEFAULT false,
    report_interval_hours INT NOT NULL DEFAULT 24,
    report_include_events BOOLEAN NOT NULL DEFAULT true,
    report_include_status BOOLEAN NOT NULL DEFAULT true,
    last_report_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO protean.notify_settings (id) VALUES (true) ON CONFLICT DO NOTHING;

-- Events accumulated since the last email report.
CREATE TABLE protean.notify_pending (
    id   BIGSERIAL PRIMARY KEY,
    ts   TIMESTAMPTZ NOT NULL DEFAULT now(),
    text TEXT NOT NULL
);
