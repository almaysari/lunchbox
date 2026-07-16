// Platform users, sessions and per-mailbox permissions.
const { getDb } = require('./db');
const { hashPassword, verifyPassword, randomToken } = require('./crypto');

const SESSION_TTL_MS = 1000 * 60 * 60 * 12;

function bootstrapAdmin(cfg) {
  const db = getDb();
  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count === 0) {
    const password = cfg.ADMIN_PASSWORD || randomToken().slice(0, 12);
    db.prepare('INSERT INTO users (email, name, password_hash, role, created_at) VALUES (?,?,?,?,?)')
      .run(cfg.ADMIN_EMAIL, 'Administrator', hashPassword(password), 'admin', Date.now());
    if (!cfg.ADMIN_PASSWORD) {
      console.log(`\n[madar] First run: admin user "${cfg.ADMIN_EMAIL}" created with password: ${password}`);
      console.log('[madar] Change it after first login, or set ADMIN_PASSWORD in .env before first run.\n');
    }
  }
}

function login(email, password) {
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND disabled = 0').get(String(email).toLowerCase().trim() === String(email).trim() ? email : email);
  if (!user || !verifyPassword(password, user.password_hash)) return null;
  const token = randomToken();
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)')
    .run(token, user.id, now, now + SESSION_TTL_MS);
  return { token, user: publicUser(user) };
}

function logout(token) {
  getDb().prepare('DELETE FROM sessions WHERE token = ?').run(String(token || ''));
}

function userForToken(token) {
  if (!token) return null;
  const db = getDb();
  const row = db.prepare(`
    SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.expires_at > ? AND u.disabled = 0`).get(String(token), Date.now());
  return row ? publicUser(row) : null;
}

function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}

function listUsers() {
  return getDb().prepare('SELECT id, email, name, role, disabled, created_at FROM users ORDER BY id').all();
}

function createUser({ email, name, password, role }) {
  const db = getDb();
  const r = db.prepare('INSERT INTO users (email, name, password_hash, role, created_at) VALUES (?,?,?,?,?)')
    .run(email, name || '', hashPassword(password), role === 'admin' ? 'admin' : 'member', Date.now());
  return Number(r.lastInsertRowid);
}

// --- per-mailbox grants ---
function grantsForUser(userId) {
  return getDb().prepare('SELECT mailbox_id, permission FROM mailbox_grants WHERE user_id = ?').all(userId);
}

function setGrant(userId, mailboxId, permission) {
  const db = getDb();
  if (!permission) {
    db.prepare('DELETE FROM mailbox_grants WHERE user_id = ? AND mailbox_id = ?').run(userId, mailboxId);
  } else {
    db.prepare(`INSERT INTO mailbox_grants (user_id, mailbox_id, permission) VALUES (?,?,?)
                ON CONFLICT(user_id, mailbox_id) DO UPDATE SET permission = excluded.permission`)
      .run(userId, mailboxId, permission === 'manage' ? 'manage' : 'read');
  }
}

function canReadMailbox(user, mailboxId) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const row = getDb().prepare('SELECT permission FROM mailbox_grants WHERE user_id = ? AND mailbox_id = ?')
    .get(user.id, mailboxId);
  return Boolean(row);
}

function readableMailboxIds(user) {
  if (!user) return [];
  if (user.role === 'admin') {
    return getDb().prepare('SELECT id FROM mailboxes').all().map(r => r.id);
  }
  return grantsForUser(user.id).map(g => g.mailbox_id);
}

module.exports = {
  bootstrapAdmin, login, logout, userForToken,
  listUsers, createUser, grantsForUser, setGrant, canReadMailbox, readableMailboxIds,
};
