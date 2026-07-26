-- Collector ingestion ledger — the durable state machine behind keeping the
-- collector's Inbox clean. One row per (collector mailbox, provider message):
--
--   state:      processed  ingested + routed to >=1 shared mailbox
--               unknown    ingested but NO recipient could be determined
--               retrying   processing failed with a RETRYABLE error — the
--                          message stays in the Zoho Inbox, which the realtime
--                          pass re-scans every tick (retry is free and
--                          idempotent: dedup makes a late success a no-op);
--                          promoted to failed after max attempts
--               failed     terminal failure (non-retryable, or retries spent)
--
--   move_state: pending    Zoho-side move to target_folder not yet performed
--               done       moved (moved_at stamped)
--               skipped    nothing to move yet (retrying rows)
--               unsupported the tenant rejected the write surface (recorded on
--                          the mailbox capabilities too) — organization is
--                          deferred, ingestion is unaffected
--               failed     move attempt errored terminally
--
-- The ledger is idempotent per provider message (UNIQUE) and drives BOTH the
-- organizer (folder moves) and the monitoring counters. Restart-safe: all
-- state lives here, nothing in process memory.
CREATE TABLE collector_ingest (
  id                  BIGSERIAL PRIMARY KEY,
  mailbox_id          BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  provider_message_id TEXT NOT NULL,
  occurrence_id       BIGINT,
  state               TEXT NOT NULL CHECK (state IN ('processed','unknown','retrying','failed')),
  routed_to           TEXT NOT NULL DEFAULT '',
  category            TEXT NOT NULL DEFAULT '',
  error               TEXT,
  error_stack         TEXT,
  retryable           BOOLEAN NOT NULL DEFAULT FALSE,
  attempts            INT NOT NULL DEFAULT 1,
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  received_at         TIMESTAMPTZ,
  processed_at        TIMESTAMPTZ,
  move_state          TEXT NOT NULL DEFAULT 'pending'
                      CHECK (move_state IN ('pending','done','skipped','unsupported','failed')),
  target_folder       TEXT NOT NULL DEFAULT '',
  moved_at            TIMESTAMPTZ,
  UNIQUE (mailbox_id, provider_message_id)
);
CREATE INDEX idx_collector_ingest_move ON collector_ingest (mailbox_id, move_state)
  WHERE move_state = 'pending';
CREATE INDEX idx_collector_ingest_state ON collector_ingest (mailbox_id, state);
