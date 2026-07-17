// Users, RBAC roles, sessions and granular per-mailbox permissions.
// No default credentials: the first admin is created ONLY via `npm run create-admin`.
const { q, all, one } = require('./db');
const { hashPassword, verifyPassword, randomToken } = require('./crypto');

const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const SESSION_ROTATE_MS = 1000 * 60 * 60;      // rotate token after 1h of age
const LOGIN_WINDOW_MIN = 15;
const LOGIN_MAX_FAILURES = 5;                  // per email per window → lockout

const GRANT_FLAGS = [
  'can_view_messages', 'can_view_attachments', 'can_download_attachments',
  'can_reply', 'can_send', 'can_manage_labels', 'can_manage_mailbox', 'can_manage_permissions',
];

// ---- RBAC ----
async function rolesForUser(userId) {
  return (await all(`SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1`, [userId]))
    .map(r => r.name);
}

function hasRole(user, ...names) {
  return Boolean(user && user.roles && names.some(n => user.roles.includes(n)));
}
// platform_admin implies everything; mail_admin covers mail-module admin actions.
const isPlatformAdmin = u => hasRole(u, 'platform_admin');
const isMailAdmin = u => hasRole(u, 'platform_admin', 'mail_admin');
const isSecurityAdmin = u => hasRole(u, 'platform_admin', 'security_admin');
const isAuditor = u => hasRole(u, 'platform_admin', 'security_admin', 'auditor');

async function assignRole(userId, roleName) {
  await q(`INSERT INTO user_roles (user_id, role_id)
           SELECT $1, id FROM roles WHERE name = $2 ON CONFLICT DO NOTHING`, [userId, roleName]);
}

async function revokeRole(userId, roleName) {
  await q(`DELETE FROM user_roles ur USING roles r WHERE ur.role_id = r.id AND ur.user_id = $1 AND r.name = $2`,
    [userId, roleName]);
}

// ---- login with DB-backed lockout (restart-safe: counts audit_log failures) ----
async function loginLocked(email) {
  const row = await one(`SELECT COUNT(*)::int AS n FROM audit_log
    WHERE action = 'auth.login.failed' AND target = $1 AND at > now() - interval '${LOGIN_WINDOW_MIN} minutes'`,
    [String(email || '').toLowerCase().trim()]);
  return row.n >= LOGIN_MAX_FAILURES;
}

async function login(email, password) {
  const normEmail = String(email || '').toLowerCase().trim();
  if (await loginLocked(normEmail)) return { locked: true };
  const user = await one('SELECT * FROM users WHERE email = $1 AND disabled = FALSE', [normEmail]);
  if (!user || !verifyPassword(password, user.password_hash)) return null;
  const token = randomToken();
  await q('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2,$3)',
    [token, user.id, new Date(Date.now() + SESSION_TTL_MS)]);
  return { token, user: await publicUser(user) };
}

async function logout(token) {
  if (token) await q('DELETE FROM sessions WHERE token = $1', [token]);
}

async function revokeAllSessions(userId) {
  await q('DELETE FROM sessions WHERE user_id = $1', [userId]);
}

// Returns { user, rotatedToken? } — sessions older than SESSION_ROTATE_MS get
// a fresh token (rotation); the old one is revoked atomically.
async function userForToken(token) {
  if (!token) return { user: null };
  const row = await one(`SELECT u.*, s.created_at AS session_created FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = $1 AND s.expires_at > now() AND u.disabled = FALSE`, [token]);
  if (!row) return { user: null };
  const user = await publicUser(row);
  if (Date.now() - new Date(row.session_created).getTime() > SESSION_ROTATE_MS) {
    const fresh = randomToken();
    await q('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2,$3)',
      [fresh, row.id, new Date(Date.now() + SESSION_TTL_MS)]);
    await q('DELETE FROM sessions WHERE token = $1', [token]);
    return { user, rotatedToken: fresh };
  }
  return { user };
}

async function publicUser(u) {
  return { id: Number(u.id), email: u.email, name: u.name, roles: await rolesForUser(u.id) };
}

function listUsers() {
  return all('SELECT id, email, name, disabled, created_at FROM users ORDER BY id');
}

async function createUser({ email, name, password, roles = ['member'] }) {
  if (!password || password.length < 12) throw new Error('Password must be at least 12 characters.');
  const r = await one('INSERT INTO users (email, name, password_hash) VALUES ($1,$2,$3) RETURNING id',
    [String(email).toLowerCase().trim(), name || '', hashPassword(password)]);
  for (const role of roles) await assignRole(Number(r.id), role);
  return Number(r.id);
}

// Password reset (admin-driven; revokes all sessions of the target user).
async function resetPassword(userId, newPassword) {
  if (!newPassword || newPassword.length < 12) throw new Error('Password must be at least 12 characters.');
  await q('UPDATE users SET password_hash = $1 WHERE id = $2', [hashPassword(newPassword), userId]);
  await revokeAllSessions(userId);
}

// ---- granular mailbox grants ----
function grantsForUser(userId) {
  return all('SELECT * FROM mailbox_grants WHERE user_id = $1', [userId]);
}

// flags: object of GRANT_FLAGS booleans; null/empty = revoke entirely.
async function setGrant(userId, mailboxId, flags) {
  if (!flags || !Object.values(flags).some(Boolean)) {
    await q('DELETE FROM mailbox_grants WHERE user_id = $1 AND mailbox_id = $2', [userId, mailboxId]);
    return;
  }
  const cols = GRANT_FLAGS;
  const vals = cols.map(c => Boolean(flags[c]));
  await q(`INSERT INTO mailbox_grants (user_id, mailbox_id, ${cols.join(',')})
    VALUES ($1,$2,${cols.map((_, i) => '$' + (i + 3)).join(',')})
    ON CONFLICT (user_id, mailbox_id) DO UPDATE SET ${cols.map(c => `${c}=EXCLUDED.${c}`).join(',')}`,
    [userId, mailboxId, ...vals]);
}

async function mailboxPermission(user, mailboxId, flag) {
  if (!user) return false;
  if (!GRANT_FLAGS.includes(flag)) throw new Error('unknown grant flag: ' + flag);
  if (isMailAdmin(user)) return true;
  const row = await one(`SELECT ${flag} AS ok FROM mailbox_grants WHERE user_id = $1 AND mailbox_id = $2`,
    [user.id, mailboxId]);
  return Boolean(row && row.ok);
}

const canReadMailbox = (user, mailboxId) => mailboxPermission(user, mailboxId, 'can_view_messages');

async function readableMailboxIds(user) {
  if (!user) return [];
  if (isMailAdmin(user)) return (await all('SELECT id FROM mailboxes')).map(r => Number(r.id));
  return (await all('SELECT mailbox_id FROM mailbox_grants WHERE user_id = $1 AND can_view_messages', [user.id]))
    .map(g => Number(g.mailbox_id));
}

module.exports = {
  login, logout, userForToken, revokeAllSessions, resetPassword, loginLocked,
  listUsers, createUser, rolesForUser, assignRole, revokeRole,
  hasRole, isPlatformAdmin, isMailAdmin, isSecurityAdmin, isAuditor,
  grantsForUser, setGrant, mailboxPermission, canReadMailbox, readableMailboxIds,
  GRANT_FLAGS,
};
