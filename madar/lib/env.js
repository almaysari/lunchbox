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
    ZOHO_CLIENT_ID: process.env.ZOHO_CLIENT_ID || '',
    ZOHO_CLIENT_SECRET: process.env.ZOHO_CLIENT_SECRET || '',
    ZOHO_REDIRECT_URI: process.env.ZOHO_REDIRECT_URI || 'http://localhost:3000/oauth/callback',
    ZOHO_ACCOUNTS_BASE: process.env.ZOHO_ACCOUNTS_BASE || 'https://accounts.zoho.com',
    ZOHO_MAIL_BASE: process.env.ZOHO_MAIL_BASE || 'https://mail.zoho.com',
    ZOHO_MAILBOX: process.env.ZOHO_MAILBOX || '',
    ZOHO_FOLDER: process.env.ZOHO_FOLDER || '',
    SYNC_INTERVAL_MINUTES: Number(process.env.SYNC_INTERVAL_MINUTES || 10),
  };
}

module.exports = { loadEnv };
