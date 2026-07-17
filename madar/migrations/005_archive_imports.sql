-- Organization-wide archive intake: one row per uploaded eDiscovery ZIP part,
-- bound to its target mailbox (message-source correctness is non-negotiable).
-- Statuses: pending -> importing -> completed | failed.
CREATE TABLE archive_imports (
  id            BIGSERIAL PRIMARY KEY,
  mailbox_id    BIGINT NOT NULL REFERENCES mailboxes(id),
  filename      TEXT NOT NULL DEFAULT '',
  size_bytes    BIGINT NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'importing', 'completed', 'failed')),
  totals        JSONB,          -- {imported, duplicates, attachments, quarantined, folders}
  error_detail  TEXT,
  uploaded_by   BIGINT REFERENCES users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at   TIMESTAMPTZ
);
CREATE INDEX idx_archive_imports_mailbox ON archive_imports(mailbox_id, id DESC);
