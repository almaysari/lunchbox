-- RBAC, canonical message model, granular grants, sync jobs, OAuth states,
-- attachment security fields, encryption key versioning.
-- Forward-only. No production data exists yet (live never ran), so the old
-- single-table message model is dropped and replaced.

-- ============ 3) RBAC: real roles tables, no role text on users ============
CREATE TABLE roles (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT ''
);

INSERT INTO roles (name, description) VALUES
  ('platform_admin', 'Full platform administration'),
  ('security_admin', 'Security configuration: connections, secrets, permissions'),
  ('mail_admin',     'Mail module administration: discovery, pilots, sync'),
  ('auditor',        'Read-only access to audit log and configuration'),
  ('member',         'Regular member; access via per-mailbox grants only');

CREATE TABLE user_roles (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- migrate existing role text, then drop it
INSERT INTO user_roles (user_id, role_id)
  SELECT u.id, r.id FROM users u JOIN roles r ON r.name = CASE u.role WHEN 'admin' THEN 'platform_admin' ELSE 'member' END;
ALTER TABLE users DROP COLUMN role;

-- ============ 4) Canonical messages + occurrences ============
DROP TABLE IF EXISTS message_labels;
DROP TABLE IF EXISTS attachments;
DROP TABLE IF EXISTS messages;

CREATE TABLE canonical_messages (
  id              BIGSERIAL PRIMARY KEY,
  dedup_hash      TEXT NOT NULL UNIQUE,            -- platform-wide identity (RFC Message-ID or fingerprint)
  rfc_message_id  TEXT NOT NULL DEFAULT '',
  thread_id       TEXT NOT NULL DEFAULT '',
  from_address    TEXT NOT NULL DEFAULT '',
  from_name       TEXT NOT NULL DEFAULT '',
  to_addresses    TEXT NOT NULL DEFAULT '',
  cc_addresses    TEXT NOT NULL DEFAULT '',
  subject         TEXT NOT NULL DEFAULT '',
  snippet         TEXT NOT NULL DEFAULT '',
  body_html       TEXT,
  sent_at         TIMESTAMPTZ NOT NULL,
  has_attachments BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  fts tsvector GENERATED ALWAYS AS (
    to_tsvector('simple', coalesce(subject,'') || ' ' || coalesce(snippet,'') || ' ' || coalesce(from_address,''))
  ) STORED
);
CREATE INDEX idx_canonical_fts ON canonical_messages USING GIN (fts);
CREATE INDEX idx_canonical_rfc ON canonical_messages(rfc_message_id) WHERE rfc_message_id <> '';

-- A message is never lost when it appears in several mailboxes/folders:
-- each appearance is an occurrence pointing at ONE canonical message.
CREATE TABLE message_occurrences (
  id                   BIGSERIAL PRIMARY KEY,
  canonical_message_id BIGINT NOT NULL REFERENCES canonical_messages(id) ON DELETE CASCADE,
  mailbox_id           BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  folder_id            BIGINT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  provider             TEXT NOT NULL DEFAULT 'zoho',
  provider_message_id  TEXT NOT NULL,
  direction            TEXT NOT NULL DEFAULT 'in' CHECK (direction IN ('in','out')),
  received_at          TIMESTAMPTZ NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (mailbox_id, folder_id, provider_message_id),   -- same provider msg once per folder
  UNIQUE (mailbox_id, folder_id, canonical_message_id)   -- same canonical once per folder
);
CREATE INDEX idx_occ_mailbox_time ON message_occurrences(mailbox_id, received_at DESC);
CREATE INDEX idx_occ_canonical ON message_occurrences(canonical_message_id);

-- ============ 5) Attachments: canonical-linked + security fields ============
CREATE TABLE attachments (
  id                     BIGSERIAL PRIMARY KEY,
  canonical_message_id   BIGINT NOT NULL REFERENCES canonical_messages(id) ON DELETE CASCADE,
  provider_attachment_id TEXT NOT NULL DEFAULT '',
  original_filename      TEXT NOT NULL,
  sanitized_filename     TEXT NOT NULL,
  size                   BIGINT NOT NULL DEFAULT 0 CHECK (size >= 0),
  provider_mime_type     TEXT NOT NULL DEFAULT '',   -- what Zoho claimed — never trusted
  detected_mime_type     TEXT NOT NULL DEFAULT '',   -- magic-bytes detection, used for serving
  quarantine_status      TEXT NOT NULL DEFAULT 'pending'
                         CHECK (quarantine_status IN ('pending','clean','quarantined')),
  storage_key            TEXT NOT NULL UNIQUE,
  sha256                 TEXT NOT NULL,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (canonical_message_id, sha256, original_filename)
);

CREATE TABLE message_labels (
  canonical_message_id BIGINT NOT NULL REFERENCES canonical_messages(id) ON DELETE CASCADE,
  label_id             BIGINT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
  PRIMARY KEY (canonical_message_id, label_id)
);

-- ============ 6) Granular mailbox grants (safe defaults: everything FALSE) ============
DROP TABLE mailbox_grants;
CREATE TABLE mailbox_grants (
  user_id                  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mailbox_id               BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  can_view_messages        BOOLEAN NOT NULL DEFAULT FALSE,
  can_view_attachments     BOOLEAN NOT NULL DEFAULT FALSE,
  can_download_attachments BOOLEAN NOT NULL DEFAULT FALSE,
  can_reply                BOOLEAN NOT NULL DEFAULT FALSE,
  can_send                 BOOLEAN NOT NULL DEFAULT FALSE,
  can_manage_labels        BOOLEAN NOT NULL DEFAULT FALSE,
  can_manage_mailbox       BOOLEAN NOT NULL DEFAULT FALSE,
  can_manage_permissions   BOOLEAN NOT NULL DEFAULT FALSE,
  granted_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, mailbox_id)
);

-- ============ 7) Sync jobs: start/pause/resume/cancel/progress ============
CREATE TABLE sync_jobs (
  id                BIGSERIAL PRIMARY KEY,
  mailbox_id        BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  status            TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','paused','cancelled','completed','failed')),
  requested_by      BIGINT REFERENCES users(id) ON DELETE SET NULL,
  discovered        INTEGER NOT NULL DEFAULT 0,
  imported          INTEGER NOT NULL DEFAULT 0,
  skipped           INTEGER NOT NULL DEFAULT 0,
  errors            INTEGER NOT NULL DEFAULT 0,
  current_folder_id BIGINT REFERENCES folders(id) ON DELETE SET NULL,
  current_cursor    INTEGER NOT NULL DEFAULT 1,
  error_detail      TEXT NOT NULL DEFAULT '',
  started_at        TIMESTAMPTZ,
  finished_at       TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sync_jobs_mailbox ON sync_jobs(mailbox_id, id DESC);
-- one live job per mailbox at a time
CREATE UNIQUE INDEX idx_sync_jobs_one_active ON sync_jobs(mailbox_id)
  WHERE status IN ('queued','running','paused');

-- ============ 10) OAuth state (CSRF protection for the authorize flow) ============
CREATE TABLE oauth_states (
  state_hash    TEXT PRIMARY KEY,                   -- sha256 of the state value; plaintext never stored
  connection_id BIGINT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  created_by    BIGINT REFERENCES users(id) ON DELETE SET NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  used_at       TIMESTAMPTZ                          -- one-time use
);
CREATE INDEX idx_oauth_states_expiry ON oauth_states(expires_at);

-- ============ 11) Encryption key versioning ============
ALTER TABLE connections ADD COLUMN encryption_key_version INTEGER NOT NULL DEFAULT 1;
