-- Live-sync / archive convergence guarantee: a canonical message appears at
-- most ONCE per mailbox, regardless of which path (live sync, routed copy,
-- archive import) or folder brought it in. Pre-existing duplicates (same
-- canonical seen through two folders of one mailbox) are collapsed keeping
-- the earliest occurrence.
DELETE FROM message_occurrences a USING message_occurrences b
 WHERE a.canonical_message_id = b.canonical_message_id
   AND a.mailbox_id = b.mailbox_id
   AND a.id > b.id;

ALTER TABLE message_occurrences
  ADD CONSTRAINT message_occurrences_mailbox_canonical_key
  UNIQUE (mailbox_id, canonical_message_id);
