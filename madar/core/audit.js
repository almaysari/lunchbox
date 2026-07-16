// Audit trail: every sensitive action (auth, connection changes, discovery,
// sync, message/attachment access) is recorded.
const { getDb } = require('./db');

function audit(userId, action, target = '', details = '') {
  getDb().prepare('INSERT INTO audit_log (at, user_id, action, target, details) VALUES (?,?,?,?,?)')
    .run(Date.now(), userId || null, action, String(target), typeof details === 'string' ? details : JSON.stringify(details));
}

function recentAudit(limit = 200) {
  return getDb().prepare(`
    SELECT a.*, u.email AS user_email FROM audit_log a
    LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.id DESC LIMIT ?`).all(limit);
}

module.exports = { audit, recentAudit };
