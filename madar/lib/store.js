// JSON-file datastore: candidates, seen message ids, tokens, sync state.
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
const CV_DIR = path.join(DATA_DIR, 'cvs');

function ensureDirs() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(CV_DIR, { recursive: true });
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

function loadDb() {
  ensureDirs();
  return readJson(DB_FILE, { candidates: [], seenMessageIds: {}, lastSync: null, lastSyncError: null });
}

function saveDb(db) {
  ensureDirs();
  writeJson(DB_FILE, db);
}

function loadTokens() {
  return readJson(TOKENS_FILE, null);
}

function saveTokens(tokens) {
  ensureDirs();
  writeJson(TOKENS_FILE, tokens);
  try { fs.chmodSync(TOKENS_FILE, 0o600); } catch {}
}

module.exports = { loadDb, saveDb, loadTokens, saveTokens, CV_DIR, DATA_DIR };
