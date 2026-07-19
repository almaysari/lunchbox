-- Durable production-acceptance state (postgres-pro: durable state over process
-- memory; docker: the sampler must survive container restarts).
--
-- The first acceptance harness kept its samples in the CLI process's memory and
-- wrote the report only at the end — a container restart (deploy, crash, host
-- reboot) killed the soak and destroyed the evidence, which is unacceptable for
-- a 72-hour run whose PURPOSE is to survive restarts. Now the run definition,
-- every sample, and every incident live in PostgreSQL; the sampler runs inside
-- the Docker-supervised server process and simply resumes the active run after
-- any restart (recording the restart itself as evidence, not losing it).
CREATE TABLE acceptance_runs (
  id            BIGSERIAL PRIMARY KEY,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','aborted')),
  planned_hours NUMERIC NOT NULL,
  sample_sec    INT NOT NULL DEFAULT 60,
  canary        TEXT,                        -- subject substring to watch for (operator-chosen, no PII)
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ends_at       TIMESTAMPTZ NOT NULL,
  finished_at   TIMESTAMPTZ,
  evaluation    JSONB,                       -- final verdict + per-check results
  created_by    BIGINT REFERENCES users(id) ON DELETE SET NULL
);
-- one active run at a time: the sampler is a singleton loop
CREATE UNIQUE INDEX idx_acceptance_one_active ON acceptance_runs ((TRUE)) WHERE status = 'active';

CREATE TABLE acceptance_samples (
  id             BIGSERIAL PRIMARY KEY,
  run_id         BIGINT NOT NULL REFERENCES acceptance_runs(id) ON DELETE CASCADE,
  at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  worker_alive   BOOLEAN NOT NULL,
  heartbeat_age_sec INT,
  worker_pid     INT,                        -- pid changes across samples = restart evidence
  stuck_jobs     INT NOT NULL DEFAULT 0,
  stuck_mailboxes INT NOT NULL DEFAULT 0,
  occurrences_total BIGINT NOT NULL DEFAULT 0,
  duplicate_occurrences INT NOT NULL DEFAULT 0,
  duplicate_canonicals  INT NOT NULL DEFAULT 0,
  transport_errors JSONB,                    -- {kind: count} within the sample window
  rss_bytes      BIGINT,
  detail         JSONB
);
CREATE INDEX idx_acceptance_samples_run ON acceptance_samples(run_id, id);

CREATE TABLE acceptance_incidents (
  id       BIGSERIAL PRIMARY KEY,
  run_id   BIGINT NOT NULL REFERENCES acceptance_runs(id) ON DELETE CASCADE,
  at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind     TEXT NOT NULL,                    -- worker_stale | stuck_job | stuck_mailbox | duplicate_detected | restart_detected | sampler_error | canary_captured
  detail   JSONB
);
CREATE INDEX idx_acceptance_incidents_run ON acceptance_incidents(run_id, id);
