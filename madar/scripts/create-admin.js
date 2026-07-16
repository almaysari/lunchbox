#!/usr/bin/env node
// One-time secure admin creation. No default credentials exist anywhere:
// this command is the only way to create the first admin.
// - prompts for name/email/password (password input is not echoed)
// - hashes with scrypt (N=2^15, r=8, p=1) via core/crypto
// - never prints the password
// Non-interactive use (CI/integration tests only): MADAR_ADMIN_EMAIL,
// MADAR_ADMIN_NAME, MADAR_ADMIN_PASSWORD env vars — never commit them.
const path = require('path');
const readline = require('readline');
const { loadEnv } = require('../core/env');
loadEnv(path.join(__dirname, '..'));
const { q, one, closeDb } = require('../core/db');
const { hashPassword } = require('../core/crypto');

function ask(question, { muted = false } = {}) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (muted) {
      // do not echo password characters
      rl.output.write(question);
      rl.input.on('data', () => {});
      const orig = rl._writeToOutput;
      rl._writeToOutput = () => {};
      rl.question('', answer => { rl._writeToOutput = orig; rl.close(); process.stdout.write('\n'); resolve(answer); });
    } else {
      rl.question(question, answer => { rl.close(); resolve(answer); });
    }
  });
}

async function main() {
  const email = (process.env.MADAR_ADMIN_EMAIL || await ask('Admin email: ')).trim().toLowerCase();
  const name = (process.env.MADAR_ADMIN_NAME || await ask('Admin name: ')).trim();
  const password = process.env.MADAR_ADMIN_PASSWORD || await ask('Admin password (min 12 chars, hidden): ', { muted: true });

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error('Invalid email.');
  if (!password || password.length < 12) throw new Error('Password must be at least 12 characters.');

  const existing = await one('SELECT id FROM users WHERE email = $1', [email]);
  if (existing) throw new Error('A user with this email already exists.');

  await q('INSERT INTO users (email, name, password_hash, role) VALUES ($1,$2,$3,$4)',
    [email, name, hashPassword(password), 'admin']);
  console.log(`Admin created: ${email}`);
  await closeDb();
}

main().catch(err => { console.error('Error:', err.message); process.exit(1); });
