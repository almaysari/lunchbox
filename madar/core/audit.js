// Audit trail (PostgreSQL, async). Details are sanitized: any value that
// looks like a token/secret is redacted before persisting.
const { q, all } = require('./db');

const SECRET_RE = /(token|secret|password|authorization)["'\s:=]+[^\s",}]{8,}/gi;

function sanitizeDetails(details) {
  const s = typeof details === 'string' ? details : JSON.stringify(details ?? '');
  return s.replace(SECRET_RE, m => m.split(/["'\s:=]+/)[0] + ':[REDACTED]');
}

async function audit(userId, action, target = '', details = '') {
  try {
    await q('INSERT INTO audit_log (user_id, action, target, details) VALUES ($1,$2,$3,$4)',
      [userId || null, action, String(target), sanitizeDetails(details)]);
  } catch (err) {
    console.error('[madar] audit write failed:', err.message);
  }
}

function recentAudit(limit = 200) {
  return all(`SELECT a.*, u.email AS user_email FROM audit_log a
    LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT $1`, [limit]);
}

module.exports = { audit, recentAudit, sanitizeDetails };
