// Single platform database (SQLite via node:sqlite — zero external deps).
// One DB for the whole company: every mailbox, message and permission lives here.
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = process.env.MADAR_DATA_DIR || path.join(__dirname, '..', 'data');
const ATTACH_DIR = path.join(DATA_DIR, 'attachments');

let db = null;

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ============ platform core ============
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,          -- scrypt: salt:hash (hex)
  role TEXT NOT NULL DEFAULT 'member',  -- admin | member
  created_at INTEGER NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  user_id INTEGER,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT ''
);

-- ============ organization connections (NOT tied to an employee) ============
CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL DEFAULT 'zoho',       -- zoho | ms365 | gmail (future)
  label TEXT NOT NULL DEFAULT '',
  accounts_base TEXT NOT NULL DEFAULT 'https://accounts.zoho.com',
  api_base TEXT NOT NULL DEFAULT 'https://mail.zoho.com',
  client_id TEXT NOT NULL,
  client_secret_enc TEXT NOT NULL,             -- AES-256-GCM
  refresh_token_enc TEXT,                      -- AES-256-GCM, set after consent
  scopes TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',      -- pending | connected | error
  status_detail TEXT NOT NULL DEFAULT '',
  created_by INTEGER REFERENCES users(id),
  created_at INTEGER NOT NULL
);

-- ============ mail module ============
-- Shared mailboxes are the PRIMARY case in this organization (20 of them
-- across exoticcolors.org and thetaurus.world) — the schema treats group
-- metadata (aliases, members, access level, moderation) as first-class.
CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'zoho',
  connection_id INTEGER REFERENCES connections(id),
  detected_type TEXT NOT NULL DEFAULT 'unknown',   -- shared_mailbox | user | distribution_list | stream_group | unknown
  strategy TEXT NOT NULL DEFAULT 'none',           -- mail_api | ediscovery_import | moderation_only | none (switchable without data loss)
  provider_account_id TEXT,                        -- Zoho accountId IF the API exposes one
  provider_group_id TEXT,                          -- Zoho group id (zgid) for group-backed mailboxes
  org_id TEXT,                                     -- Zoho zoid
  access_level TEXT NOT NULL DEFAULT '',           -- everyone | organization_members | only_moderators | ...
  members TEXT NOT NULL DEFAULT '[]',              -- JSON [{email, role}]
  moderators TEXT NOT NULL DEFAULT '[]',           -- JSON [email]
  moderation_count INTEGER NOT NULL DEFAULT 0,
  capabilities TEXT NOT NULL DEFAULT '{}',         -- JSON: proven-by-probe read access {folders, messages, attachments, sent, evidence}
  is_pilot INTEGER NOT NULL DEFAULT 0,             -- sync runs ONLY for pilot-selected mailboxes
  status TEXT NOT NULL DEFAULT 'new',              -- new | detecting | detected | ready | syncing | error | no_live_api
  status_detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

-- Aliases (+N addresses in the admin console). Unique platform-wide so an
-- alias can never be registered as a second, duplicate mailbox.
CREATE TABLE IF NOT EXISTS mailbox_aliases (
  address TEXT PRIMARY KEY,
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id)
);

CREATE TABLE IF NOT EXISTS detection_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_id INTEGER NOT NULL,                      -- mailbox id, or 0 for organization-scope reports
  at INTEGER NOT NULL,
  report TEXT NOT NULL                              -- raw JSON evidence
);

CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
  provider_folder_id TEXT NOT NULL,
  name TEXT NOT NULL,
  folder_type TEXT NOT NULL DEFAULT '',
  UNIQUE(mailbox_id, provider_folder_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
  folder_id INTEGER REFERENCES folders(id),
  provider_message_id TEXT NOT NULL,
  rfc_message_id TEXT NOT NULL DEFAULT '',
  dedup_hash TEXT NOT NULL,                        -- platform-wide duplicate guard
  thread_id TEXT NOT NULL DEFAULT '',
  from_address TEXT NOT NULL DEFAULT '',
  from_name TEXT NOT NULL DEFAULT '',
  to_addresses TEXT NOT NULL DEFAULT '',
  cc_addresses TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  snippet TEXT NOT NULL DEFAULT '',
  body_html TEXT,
  received_at INTEGER NOT NULL,
  direction TEXT NOT NULL DEFAULT 'in',            -- in | out
  has_attachments INTEGER NOT NULL DEFAULT 0,
  UNIQUE(mailbox_id, provider_message_id)
);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_time ON messages(mailbox_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_dedup ON messages(dedup_hash);

CREATE TABLE IF NOT EXISTS attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL REFERENCES messages(id),
  name TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  mime TEXT NOT NULL DEFAULT '',
  file_path TEXT NOT NULL,                          -- relative to data/attachments
  sha256 TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS labels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  color TEXT NOT NULL DEFAULT '#2545d3'
);

CREATE TABLE IF NOT EXISTS message_labels (
  message_id INTEGER NOT NULL REFERENCES messages(id),
  label_id INTEGER NOT NULL REFERENCES labels(id),
  PRIMARY KEY (message_id, label_id)
);

-- per-user permission on each mailbox
CREATE TABLE IF NOT EXISTS mailbox_grants (
  user_id INTEGER NOT NULL REFERENCES users(id),
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
  permission TEXT NOT NULL DEFAULT 'read',          -- read | manage
  PRIMARY KEY (user_id, mailbox_id)
);

CREATE TABLE IF NOT EXISTS sync_state (
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
  folder_id INTEGER NOT NULL REFERENCES folders(id),
  backfill_done INTEGER NOT NULL DEFAULT 0,
  next_start INTEGER NOT NULL DEFAULT 1,            -- backfill pagination cursor
  last_sync_at INTEGER,
  last_error TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (mailbox_id, folder_id)
);

-- full-text search over all company mail
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
  subject, snippet, from_address, content='messages', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts(rowid, subject, snippet, from_address)
  VALUES (new.id, new.subject, new.snippet, new.from_address);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, subject, snippet, from_address)
  VALUES ('delete', old.id, old.subject, old.snippet, old.from_address);
END;
`;

function getDb() {
  if (db) return db;
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(ATTACH_DIR, { recursive: true });
  db = new DatabaseSync(path.join(DATA_DIR, 'madar.db'));
  db.exec(SCHEMA);
  return db;
}

module.exports = { getDb, DATA_DIR, ATTACH_DIR };
