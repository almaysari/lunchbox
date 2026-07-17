#!/usr/bin/env node
// Password reset strategy (admin-driven, no email flow yet):
// an operator with DB access resets a user's password; ALL sessions of that
// user are revoked. The new password is prompted hidden and never printed.
// Usage: npm run reset-password  (or MADAR_RESET_EMAIL / MADAR_RESET_PASSWORD env for CI)
const path = require('path');
const { askVisible, askHiddenConfirmed } = require('./lib-prompt');
const { loadEnv } = require('../core/env');
loadEnv(path.join(__dirname, '..'));
const { q, one, closeDb } = require('../core/db');
const { hashPassword } = require('../core/crypto');


async function main() {
  const email = (process.env.MADAR_RESET_EMAIL || await askVisible('User email: ')).trim().toLowerCase();
  const password = process.env.MADAR_RESET_PASSWORD || await askHiddenConfirmed('New password');
  if (!password || password.length < 12) throw new Error('Password must be at least 12 characters.');
  const userRow = await one('SELECT id FROM users WHERE email = $1', [email]);
  if (!userRow) throw new Error('No user with this email.');
  await q('UPDATE users SET password_hash = $1 WHERE id = $2', [hashPassword(password), userRow.id]);
  await q('DELETE FROM sessions WHERE user_id = $1', [userRow.id]);
  console.log(`Password reset for ${email}; all sessions revoked.`);
  await closeDb();
}

main().catch(err => { console.error('Error:', err.message); process.exit(1); });
