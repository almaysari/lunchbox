// Minimal .env loader — file values never override real environment variables.
const fs = require('fs');
const path = require('path');

function loadEnv(dir) {
  // Local-dev convenience only: inside Docker the file does not exist
  // (.dockerignore) and configuration arrives via process.env (env_file).
  // Missing or unreadable file is silently fine — never fatal, never logged.
  const file = path.join(dir, '.env');
  let text = null;
  try { fs.accessSync(file, fs.constants.R_OK); text = fs.readFileSync(file, 'utf8'); } catch { /* env-only mode */ }
  if (text) {
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
    }
  }
  const cfg = {
    MODE: process.env.MODE || 'demo',
    PORT: Number(process.env.PORT || 3000),
    BASE_URL: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
    DATABASE_URL: process.env.DATABASE_URL || '',
    // Split secrets: at-rest encryption / session signing / CSRF tokens.
    MADAR_ENCRYPTION_KEY: process.env.MADAR_ENCRYPTION_KEY || '',
    MADAR_SESSION_SECRET: process.env.MADAR_SESSION_SECRET || '',
    MADAR_CSRF_SECRET: process.env.MADAR_CSRF_SECRET || '',
    SYNC_INTERVAL_MINUTES: Number(process.env.SYNC_INTERVAL_MINUTES || 10),
    MAX_ATTACHMENT_MB: Number(process.env.MAX_ATTACHMENT_MB || 25),
  };
  return cfg;
}

// Strict validation: both secrets must be >= 64 hex chars (32 bytes).
// Generate with: openssl rand -hex 32
function validateSecrets(cfg) {
  const errors = [];
  const keys = ['MADAR_ENCRYPTION_KEY', 'MADAR_SESSION_SECRET', 'MADAR_CSRF_SECRET'];
  for (const key of keys) {
    if (!/^[0-9a-fA-F]{64,}$/.test(cfg[key])) {
      errors.push(`${key} must be at least 64 hex characters (openssl rand -hex 32).`);
    }
  }
  const values = keys.map(k => cfg[k]).filter(Boolean);
  if (new Set(values).size !== values.length) {
    errors.push('MADAR_ENCRYPTION_KEY / MADAR_SESSION_SECRET / MADAR_CSRF_SECRET must all be different values.');
  }
  return errors;
}

// Encryption keyring for rotation: MADAR_ENCRYPTION_KEY is version 1,
// MADAR_ENCRYPTION_KEY_V2, _V3... add newer versions (highest wins for new writes).
function encryptionKeyring(cfg) {
  const ring = { 1: cfg.MADAR_ENCRYPTION_KEY };
  for (const [name, value] of Object.entries(process.env)) {
    const m = name.match(/^MADAR_ENCRYPTION_KEY_V(\d+)$/);
    if (m && /^[0-9a-fA-F]{64,}$/.test(value)) ring[Number(m[1])] = value;
  }
  return ring;
}

module.exports = { loadEnv, validateSecrets, encryptionKeyring };
