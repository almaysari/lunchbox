// Platform users, sessions and per-mailbox permissions (PostgreSQL, async).
// No default credentials: the first admin is created ONLY via `npm run create-admin`.
const { q, all, one } = require('./db');
const { hashPassword, verifyPassword, randomToken } = require('./crypto');

const SESSION_TTL_MS = 1000 * 60 * 60 * 12;

async function login(email, password) {
  const user = await one('SELECT * FROM users WHERE email = $1 AND disabled = FALSE', [String(email || '').toLowerCase().trim()]);
  if (!user || !verifyPassword(password, user.password_hash)) return null;
  const token = randomToken();
  await q('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2,$3)',
    [token, user.id, new Date(Date.now() + SESSION_TTL_MS)]);
  return { token, user: publicUser(user) };
}

async function logout(token) {
  if (token) await q('DELETE FROM sessions WHERE token = $1', [token]);
}

async function userForToken(token) {
  if (!token) return null;
  const row = await one(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token = $1 AND s.expires_at > now() AND u.disabled = FALSE`, [token]);
  return row ? publicUser(row) : null;
}

function publicUser(u) {
  return { id: Number(u.id), email: u.email, name: u.name, role: u.role };
}

function listUsers() {
  return all('SELECT id, email, name, role, disabled, created_at FROM users ORDER BY id');
}

async function createUser({ email, name, password, role }) {
  if (!password || password.length < 12) throw new Error('Password must be at least 12 characters.');
  const r = await one('INSERT INTO users (email, name, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING id',
    [String(email).toLowerCase().trim(), name || '', hashPassword(password), role === 'admin' ? 'admin' : 'member']);
  return Number(r.id);
}

function grantsForUser(userId) {
  return all('SELECT mailbox_id, permission FROM mailbox_grants WHERE user_id = $1', [userId]);
}

async function setGrant(userId, mailboxId, permission) {
  if (!permission) {
    await q('DELETE FROM mailbox_grants WHERE user_id = $1 AND mailbox_id = $2', [userId, mailboxId]);
  } else {
    await q(`INSERT INTO mailbox_grants (user_id, mailbox_id, permission) VALUES ($1,$2,$3)
             ON CONFLICT (user_id, mailbox_id) DO UPDATE SET permission = EXCLUDED.permission`,
      [userId, mailboxId, permission === 'manage' ? 'manage' : 'read']);
  }
}

async function canReadMailbox(user, mailboxId) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  return Boolean(await one('SELECT 1 FROM mailbox_grants WHERE user_id = $1 AND mailbox_id = $2', [user.id, mailboxId]));
}

async function readableMailboxIds(user) {
  if (!user) return [];
  if (user.role === 'admin') return (await all('SELECT id FROM mailboxes')).map(r => Number(r.id));
  return (await grantsForUser(user.id)).map(g => Number(g.mailbox_id));
}

module.exports = { login, logout, userForToken, listUsers, createUser, grantsForUser, setGrant, canReadMailbox, readableMailboxIds };
