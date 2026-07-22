-- Container reality: the worker's PID is ALWAYS 1 inside Docker, so pid-based
-- restart detection recorded "no restart occurred" through seven real
-- restarts while their downtime samples failed worker_uptime — a structurally
-- false verdict. The worker's BOOT IDENTITY is the heartbeat's started_at:
-- it changes on every boot regardless of pid. Persisted per sample so
-- evaluation can (a) detect restarts retroactively and (b) excuse the brief
-- stale/stuck samples inside a restart's grace window instead of counting
-- planned deploys as uptime failures.
ALTER TABLE acceptance_samples ADD COLUMN IF NOT EXISTS worker_started_at TIMESTAMPTZ;
