-- Collision metrics for Canonical Identity v3 — recorded IN the system at
-- ingestion, using the RFC Message-ID (when the archive provides it) as an
-- independent forensic oracle to measure fp3 quality on PRODUCTION data.
-- No "collision is near-impossible" hand-waving: every event is a row.
CREATE TABLE fingerprint_metrics (
  id             BIGSERIAL PRIMARY KEY,
  event_type     TEXT NOT NULL,          -- false_merge_prevented | false_split_detected | duplicate_prevented | time_unlinkable
  fp3            TEXT,                    -- the fingerprint involved
  rfc_incoming   TEXT,                    -- forensic: incoming RFC Message-ID
  rfc_existing   TEXT,                    -- forensic: the canonical's stored RFC Message-ID
  canonical_a    BIGINT,
  canonical_b    BIGINT,
  mailbox_id     BIGINT,
  detail         TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_fp_metrics_type ON fingerprint_metrics(event_type, id DESC);

-- (The forensic index on canonical_messages(rfc_message_id) already exists from
-- migration 002 — idx_canonical_rfc — and now serves as the RFC oracle lookup.)
