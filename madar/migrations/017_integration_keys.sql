-- Accounting integration layer: machine API keys over shared mailboxes.
-- The key SECRET is never stored — only its sha256 hash (verify) and a short
-- display prefix (identify in the admin UI). Scope is explicit per mailbox:
-- creating a key with a mailbox list IS the machine-access grant (admin-only,
-- audited as admin.integration_key.create/revoke). Cursors give each consumer
-- its own durable "unread" position per mailbox.
CREATE TABLE integration_keys (
  id           BIGSERIAL PRIMARY KEY,
  name         TEXT NOT NULL,
  key_hash     TEXT NOT NULL UNIQUE,          -- sha256(secret); secret shown exactly once
  key_prefix   TEXT NOT NULL DEFAULT '',      -- e.g. mik_1a2b3c4d… (identification only)
  created_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at   TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);

CREATE TABLE integration_key_mailboxes (
  key_id     BIGINT NOT NULL REFERENCES integration_keys(id) ON DELETE CASCADE,
  mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  PRIMARY KEY (key_id, mailbox_id)
);

CREATE TABLE integration_cursors (
  key_id             BIGINT NOT NULL REFERENCES integration_keys(id) ON DELETE CASCADE,
  mailbox_id         BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  last_occurrence_id BIGINT NOT NULL DEFAULT 0,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (key_id, mailbox_id)
);
