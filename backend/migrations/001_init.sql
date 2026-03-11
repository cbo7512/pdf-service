-- ═══════════════════════════════════════════════════════
--  DocFlow — PostgreSQL Schema
--  Migration: 001_init
-- ═══════════════════════════════════════════════════════

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── USERS ────────────────────────────────────────────────────────────────────
-- Unified table for USER, CONTROLLER, ADMIN roles
CREATE TABLE IF NOT EXISTS users (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(255) UNIQUE NOT NULL,
    name       VARCHAR(100) NOT NULL DEFAULT '',
    surname    VARCHAR(100) NOT NULL DEFAULT '',
    role       VARCHAR(20)  NOT NULL DEFAULT 'USER',  -- USER | CONTROLLER | ADMIN
    password   TEXT,                                   -- bcrypt hash (ADMIN only)
    active     BOOLEAN      NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── BACKUP CODES ─────────────────────────────────────────────────────────────
-- 3 emergency codes per user, generated at first login
CREATE TABLE IF NOT EXISTS backup_codes (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code       CHAR(8)     NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── OTP STORE ────────────────────────────────────────────────────────────────
-- Ephemeral table — cleaned on each new OTP for same email
CREATE TABLE IF NOT EXISTS otp_codes (
    email      VARCHAR(255) PRIMARY KEY,
    code       CHAR(6)      NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL
);

-- ─── USER ↔ CONTROLLER ASSIGNMENTS ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_controller_map (
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    controller_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id)
);

-- ─── FILES ────────────────────────────────────────────────────────────────────
-- Represents an uploaded PDF + its lifecycle state
CREATE TABLE IF NOT EXISTS files (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    original_name  VARCHAR(500) NOT NULL,
    stored_path    VARCHAR(1000) NOT NULL,        -- /uploads/<uuid>.pdf
    modified_path  VARCHAR(1000),                 -- /uploads/<uuid>_mod.pdf (after edits applied)
    size_bytes     BIGINT       NOT NULL,
    uploaded_by    UUID         NOT NULL REFERENCES users(id),
    pdf_session_id VARCHAR(100),                  -- PyMuPDF service session
    mod_session_id VARCHAR(100),                  -- modified version session
    status         VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    -- ACTIVE → file in /uploads, expires_at = +72h
    -- ARCHIVED → file zipped in /archives, archived_at set
    -- DELETED → file removed, deletion logged
    expires_at     TIMESTAMPTZ  NOT NULL,
    archived_at    TIMESTAMPTZ,
    deleted_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── TICKETS ──────────────────────────────────────────────────────────────────
-- Approval request tied to a file
CREATE TABLE IF NOT EXISTS tickets (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id       UUID        NOT NULL REFERENCES files(id),
    requester_id  UUID        NOT NULL REFERENCES users(id),
    controller_id UUID        NOT NULL REFERENCES users(id),
    status        VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    -- PENDING | APPROVED | REJECTED | ARCHIVED | DELETED
    changes       JSONB       NOT NULL DEFAULT '[]',   -- [{desc, page}]
    edit_payload  JSONB,                               -- {edits:[...]} for /apply
    note          TEXT,
    reject_reason TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at   TIMESTAMPTZ
);

-- ─── AUDIT LOGS ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    type       VARCHAR(50) NOT NULL,
    icon       VARCHAR(10) NOT NULL DEFAULT '📋',
    msg        TEXT        NOT NULL,
    detail     TEXT,
    user_email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── APP CONFIG ───────────────────────────────────────────────────────────────
-- Key-value store for application-wide settings
CREATE TABLE IF NOT EXISTS app_config (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT         NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Seed default config values
INSERT INTO app_config (key, value) VALUES
    ('setup_done',        'false'),
    ('smtp_host',         ''),
    ('smtp_port',         '587'),
    ('smtp_sec',          'tls'),
    ('smtp_user',         ''),
    ('smtp_pw',           ''),
    ('smtp_from',         ''),
    ('smtp_otp_enabled',  'true'),
    ('smtp_notif_enabled','true'),
    ('hint_user_email',   'kullanici@sirket.com'),
    ('hint_admin_email',  'admin@sirket.com'),
    ('branding_color',    '#2563eb'),
    ('branding_logo',     '')
ON CONFLICT (key) DO NOTHING;

-- ─── INDEXES ──────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_files_uploaded_by   ON files(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_files_status        ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_expires_at    ON files(expires_at);
CREATE INDEX IF NOT EXISTS idx_tickets_requester   ON tickets(requester_id);
CREATE INDEX IF NOT EXISTS idx_tickets_controller  ON tickets(controller_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status      ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created  ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_backup_codes_user   ON backup_codes(user_id);
