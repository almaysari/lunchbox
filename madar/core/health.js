// Health probes.
//  /health/live  — process liveness only (no dependencies touched).
//  /health/ready — fails unless: PostgreSQL reachable, all migrations applied,
//                  attachment storage writable, encryption configured.
// Readiness is cheap (one SELECT + one tiny file write) and never exposes
// internals beyond a boolean per subsystem.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function readiness({ db, storageDir, cryptoReady, migrationsDir }) {
  const checks = { database: false, migrations: false, storage: false, encryption: Boolean(cryptoReady) };
  try {
    checks.database = await db.healthy();
    if (checks.database) {
      const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql'));
      const applied = await db.all('SELECT name FROM schema_migrations');
      const appliedSet = new Set(applied.map(r => r.name));
      checks.migrations = files.every(f => appliedSet.has(f));
    }
  } catch { /* database stays false */ }
  try {
    const probe = path.join(storageDir, '.ready-' + crypto.randomBytes(4).toString('hex'));
    fs.writeFileSync(probe, 'x'); fs.unlinkSync(probe);
    checks.storage = true;
  } catch { /* storage stays false */ }
  return { ready: Object.values(checks).every(Boolean), checks };
}

module.exports = { readiness };
