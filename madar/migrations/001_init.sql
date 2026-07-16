-- Madar initial schema (PostgreSQL).
-- Migrations are FORWARD-ONLY (documented in docs/DECISIONS.md): fixes ship
-- as new migrations; each migration runs inside a single transaction.

CREATE TABLE users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,                     -- scrypt: salt:hash (hex)
  role          TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
  disabled      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  token      TEXT PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE audit_log (
  id      BIGSERIAL PRIMARY KEY,
  at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  action  TEXT NOT NULL,
  target  TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_at ON audit_log(at DESC);

-- Organization-owned provider connections (never tied to an employee).
CREATE TABLE connections (
  id                BIGSERIAL PRIMARY KEY,
  provider          TEXT NOT NULL DEFAULT 'zoho',
  label             TEXT NOT NULL DEFAULT '',
  accounts_base     TEXT NOT NULL DEFAULT 'https://accounts.zoho.com',
  api_base          TEXT NOT NULL DEFAULT 'https://mail.zoho.com',
  client_id         TEXT NOT NULL,
  client_secret_enc TEXT NOT NULL,                 -- AES-256-GCM
  refresh_token_enc TEXT,                          -- AES-256-GCM
  scopes            TEXT NOT NULL DEFAULT '',
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','connected','error')),
  status_detail     TEXT NOT NULL DEFAULT '',
  created_by        BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Shared mailboxes are the PRIMARY case in this organization: group metadata
-- (aliases, members, access level, moderation) is first-class.
CREATE TABLE mailboxes (
  id                  BIGSERIAL PRIMARY KEY,
  address             TEXT NOT NULL UNIQUE,
  display_name        TEXT NOT NULL DEFAULT '',
  provider            TEXT NOT NULL DEFAULT 'zoho',
  connection_id       BIGINT REFERENCES connections(id) ON DELETE SET NULL,
  detected_type       TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (detected_type IN ('shared_mailbox','user','distribution_list','stream_group','unknown')),
  strategy            TEXT NOT NULL DEFAULT 'none'
                      CHECK (strategy IN ('mail_api','ediscovery_import','moderation_only','none')),
  provider_account_id TEXT,
  provider_group_id   TEXT,
  org_id              TEXT,
  access_level        TEXT NOT NULL DEFAULT '',
  members             JSONB NOT NULL DEFAULT '[]',
  moderators          JSONB NOT NULL DEFAULT '[]',
  moderation_count    INTEGER NOT NULL DEFAULT 0,
  capabilities        JSONB NOT NULL DEFAULT '{}',
  is_pilot            BOOLEAN NOT NULL DEFAULT FALSE,
  sync_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
  status              TEXT NOT NULL DEFAULT 'new',
  status_detail       TEXT NOT NULL DEFAULT '',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Aliases: unique platform-wide so an alias can never become a second mailbox.
CREATE TABLE mailbox_aliases (
  address    TEXT PRIMARY KEY,
  mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE
);

CREATE TABLE detection_reports (
  id         BIGSERIAL PRIMARY KEY,
  mailbox_id BIGINT NOT NULL DEFAULT 0,            -- 0 = organization-scope report
  at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  report     JSONB NOT NULL
);
CREATE INDEX idx_detection_mailbox ON detection_reports(mailbox_id, id DESC);

CREATE TABLE folders (
  id                 BIGSERIAL PRIMARY KEY,
  mailbox_id         BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  provider_folder_id TEXT NOT NULL,
  name               TEXT NOT NULL,
  folder_type        TEXT NOT NULL DEFAULT '',
  UNIQUE (mailbox_id, provider_folder_id)
);

CREATE TABLE messages (
  id                  BIGSERIAL PRIMARY KEY,
  mailbox_id          BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  folder_id           BIGINT REFERENCES folders(id) ON DELETE SET NULL,
  provider_message_id TEXT NOT NULL,
  rfc_message_id      TEXT NOT NULL DEFAULT '',
  dedup_hash          TEXT NOT NULL,
  thread_id           TEXT NOT NULL DEFAULT '',
  from_address        TEXT NOT NULL DEFAULT '',
  from_name           TEXT NOT NULL DEFAULT '',
  to_addresses        TEXT NOT NULL DEFAULT '',
  cc_addresses        TEXT NOT NULL DEFAULT '',
  subject             TEXT NOT NULL DEFAULT '',
  snippet             TEXT NOT NULL DEFAULT '',
  body_html           TEXT,
  received_at         TIMESTAMPTZ NOT NULL,
  direction           TEXT NOT NULL DEFAULT 'in' CHECK (direction IN ('in','out')),
  has_attachments     BOOLEAN NOT NULL DEFAULT FALSE,
  -- duplicate guards: provider id per mailbox + content fingerprint per mailbox
  UNIQUE (mailbox_id, provider_message_id),
  UNIQUE (mailbox_id, dedup_hash)
);
CREATE INDEX idx_messages_mailbox_time ON messages(mailbox_id, received_at DESC);

-- Full-text search over all company mail (generated tsvector + GIN).
ALTER TABLE messages ADD COLUMN fts tsvector
  GENERATED ALWAYS AS (
    to_tsvector('simple', coalesce(subject,'') || ' ' || coalesce(snippet,'') || ' ' || coalesce(from_address,''))
  ) STORED;
CREATE INDEX idx_messages_fts ON messages USING GIN (fts);

CREATE TABLE attachments (
  id          BIGSERIAL PRIMARY KEY,
  message_id  BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  size        BIGINT NOT NULL DEFAULT 0,
  mime        TEXT NOT NULL DEFAULT '',
  storage_key TEXT NOT NULL UNIQUE,                -- opaque random key, resolved by the storage layer
  sha256      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE labels (
  id    BIGSERIAL PRIMARY KEY,
  name  TEXT NOT NULL UNIQUE,
  color TEXT NOT NULL DEFAULT '#2545d3'
);

CREATE TABLE message_labels (
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  label_id   BIGINT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
  PRIMARY KEY (message_id, label_id)
);

CREATE TABLE mailbox_grants (
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  permission TEXT NOT NULL DEFAULT 'read' CHECK (permission IN ('read','manage')),
  PRIMARY KEY (user_id, mailbox_id)
);

CREATE TABLE sync_state (
  mailbox_id    BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  folder_id     BIGINT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  backfill_done BOOLEAN NOT NULL DEFAULT FALSE,
  next_start    INTEGER NOT NULL DEFAULT 1,
  last_sync_at  TIMESTAMPTZ,
  last_error    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (mailbox_id, folder_id)
);
