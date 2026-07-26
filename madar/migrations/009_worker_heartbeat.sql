-- Cross-process worker observability. The live-sync worker runs INSIDE the main
-- server process; its enabled/last-tick state lived only in that process's
-- memory. Any other process (the CLI doctor, a second worker, a health probe)
-- reading that singleton saw enabled=false and wrongly concluded "worker is OFF"
-- even while the real worker logged "live sync worker started". Persist the
-- heartbeat so worker status is read from the DATABASE — the single source of
-- truth every process shares — not from a process-local variable.
CREATE TABLE sync_worker_heartbeat (
  id            BOOLEAN PRIMARY KEY DEFAULT TRUE,   -- singleton row (id = TRUE)
  enabled       BOOLEAN NOT NULL DEFAULT FALSE,
  interval_sec  INT     NOT NULL DEFAULT 120,
  pid           INT,
  hostname      TEXT,
  started_at    TIMESTAMPTZ,
  last_tick_at  TIMESTAMPTZ,
  next_tick_at  TIMESTAMPTZ,
  ticking       BOOLEAN NOT NULL DEFAULT FALSE,
  last_result   JSONB,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT sync_worker_heartbeat_singleton CHECK (id = TRUE)
);

-- One row PER worker cycle, so "does the MAIN worker succeed or fail" is provable
-- independently of any forced CLI tick. source distinguishes who ran the cycle:
--   'worker' = the background loop in the main server process
--   'cli'    = a forced tick from scripts/livesync-doctor.js --force
--   'manual' = an operator's /api/mail/live-sync/tick call
CREATE TABLE sync_worker_cycles (
  id           BIGSERIAL PRIMARY KEY,
  source       TEXT NOT NULL DEFAULT 'worker',
  pid          INT,
  ok           BOOLEAN NOT NULL DEFAULT TRUE,
  synced       INT NOT NULL DEFAULT 0,
  failed       INT NOT NULL DEFAULT 0,
  skipped_busy INT NOT NULL DEFAULT 0,
  skipped_backoff INT NOT NULL DEFAULT 0,
  recovered    INT NOT NULL DEFAULT 0,
  duration_ms  INT,
  result       JSONB,           -- full per-cycle summary incl. per-mailbox errors
  error        TEXT,            -- set when the cycle loop itself threw
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_worker_cycles_recent ON sync_worker_cycles(id DESC);
CREATE INDEX idx_worker_cycles_source ON sync_worker_cycles(source, id DESC);
