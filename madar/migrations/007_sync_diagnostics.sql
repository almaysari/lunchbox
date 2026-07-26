-- Full observability for every live-sync cycle: one row per mailbox per cycle
-- attempt, capturing the stage reached, counts, and — on failure — the typed
-- context (HTTP endpoint/status/body, or SQL state/constraint, or routing
-- decision) plus the COMPLETE stack. No more silent "internal error".
CREATE TABLE sync_diagnostics (
  id              BIGSERIAL PRIMARY KEY,
  trace_id        TEXT NOT NULL,
  mailbox_id      BIGINT REFERENCES mailboxes(id) ON DELETE CASCADE,
  mailbox_address TEXT NOT NULL DEFAULT '',
  stage           TEXT NOT NULL DEFAULT '',        -- load_state|list_folders|fetch_messages|parse|routing|db_tx|fts|body|attachments|done
  endpoint        TEXT,                            -- last Zoho endpoint touched
  http_status     INT,
  response_sample JSONB,                           -- sanitized (field names / status only)
  read_count      INT NOT NULL DEFAULT 0,
  inserted_count  INT NOT NULL DEFAULT 0,
  skipped_count   INT NOT NULL DEFAULT 0,
  routed_count    INT NOT NULL DEFAULT 0,
  outcome         TEXT NOT NULL DEFAULT 'ok',       -- ok|error
  error_class     TEXT,                            -- e.g. ZohoApiError | DbError | RoutingError | Error
  error_message   TEXT,
  error_stack     TEXT,
  sql_state       TEXT,                            -- pg SQLSTATE
  constraint_name TEXT,
  routing_context JSONB,                           -- {messageId, sourceMailbox, target, decision}
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sync_diag_mailbox ON sync_diagnostics(mailbox_id, id DESC);
CREATE INDEX idx_sync_diag_trace ON sync_diagnostics(trace_id);
