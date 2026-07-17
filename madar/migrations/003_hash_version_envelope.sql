-- Canonicalization versioning + occurrence-specific envelope privacy.

-- 12) dedup hash algorithm is versioned: changing the algorithm later must
-- never break or re-merge existing messages (old rows keep their version).
ALTER TABLE canonical_messages ADD COLUMN canonical_hash_version INTEGER NOT NULL DEFAULT 2;

-- 13) BCC / envelope privacy: To/CC/BCC as seen by a SPECIFIC mailbox copy are
-- occurrence data, not canonical data. The canonical row keeps only the safe,
-- header-derived fields common to the message; each occurrence stores the
-- envelope exactly as its own mailbox received it, and it is only ever shown
-- to users authorized on THAT mailbox.
ALTER TABLE message_occurrences ADD COLUMN envelope_to  TEXT NOT NULL DEFAULT '';
ALTER TABLE message_occurrences ADD COLUMN envelope_cc  TEXT NOT NULL DEFAULT '';
ALTER TABLE message_occurrences ADD COLUMN envelope_bcc TEXT NOT NULL DEFAULT '';
