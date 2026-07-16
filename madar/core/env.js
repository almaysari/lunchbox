// Minimal .env loader — no external dependencies.
const fs = require('fs');
const path = require('path');

function loadEnv(dir) {
  const file = path.join(dir, '.env');
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
    }
  }
  return {
    MODE: process.env.MODE || 'demo',
    PORT: Number(process.env.PORT || 3000),
    BASE_URL: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
    // Secret for encrypting stored OAuth tokens + signing sessions.
    MADAR_SECRET: process.env.MADAR_SECRET || '',
    // First-run admin bootstrap.
    ADMIN_EMAIL: process.env.ADMIN_EMAIL || 'admin@local',
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || '',
    SYNC_INTERVAL_MINUTES: Number(process.env.SYNC_INTERVAL_MINUTES || 10),
  };
}

module.exports = { loadEnv };
