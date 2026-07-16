// Minimal .env loader — file values never override real environment variables.
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
  const cfg = {
    MODE: process.env.MODE || 'demo',
    PORT: Number(process.env.PORT || 3000),
    BASE_URL: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
    DATABASE_URL: process.env.DATABASE_URL || '',
    // Split secrets: token/secret encryption vs session cookie signing.
    MADAR_ENCRYPTION_KEY: process.env.MADAR_ENCRYPTION_KEY || '',
    MADAR_SESSION_SECRET: process.env.MADAR_SESSION_SECRET || '',
    SYNC_INTERVAL_MINUTES: Number(process.env.SYNC_INTERVAL_MINUTES || 10),
    MAX_ATTACHMENT_MB: Number(process.env.MAX_ATTACHMENT_MB || 25),
  };
  return cfg;
}

// Strict validation: both secrets must be >= 64 hex chars (32 bytes).
// Generate with: openssl rand -hex 32
function validateSecrets(cfg) {
  const errors = [];
  for (const key of ['MADAR_ENCRYPTION_KEY', 'MADAR_SESSION_SECRET']) {
    const v = cfg[key];
    if (!/^[0-9a-fA-F]{64,}$/.test(v)) {
      errors.push(`${key} must be at least 64 hex characters (openssl rand -hex 32).`);
    }
  }
  if (cfg.MADAR_ENCRYPTION_KEY && cfg.MADAR_ENCRYPTION_KEY === cfg.MADAR_SESSION_SECRET) {
    errors.push('MADAR_ENCRYPTION_KEY and MADAR_SESSION_SECRET must be different values.');
  }
  return errors;
}

module.exports = { loadEnv, validateSecrets };
