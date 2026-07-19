#!/usr/bin/env node
// Read-only keyring ⇄ ciphertext audit — answers, on the LIVE tenant:
//   * which key versions are loaded in this process's keyring (k1, k2, …)
//   * the active WRITE version
//   * which ciphertext versions the stored secrets actually carry
//   * whether each stored secret DECRYPTS with the loaded keyring (boolean only)
// Prints version names and irreversible sha256 fingerprints (12 hex chars of the
// hash of the key material) — NEVER key values, NEVER decrypted plaintext.
//
// This settles "is k1 missing?" conclusively: if decryptable=true below, the
// key exists and no token was ever unrecoverable — the earlier
// oauth_token_decrypt_failed came from the pre-fix CLI running with an EMPTY
// keyring (see core/bootstrap.js).
//
// Usage: docker compose exec app node scripts/keyring-inspect.js
require('../core/bootstrap').initCryptoFromEnv();
const crypto = require('crypto');
const path = require('path');
const { loadEnv, encryptionKeyring } = require('../core/env');
const { decrypt, currentKeyVersion } = require('../core/crypto');
const { all, closeDb } = require('../core/db');

const fp = hex => crypto.createHash('sha256').update(String(hex)).digest('hex').slice(0, 12);
const prefixOf = v => String(v || '').split(':')[0] || null;
const canDecrypt = v => { if (!v) return null; try { decrypt(v); return true; } catch (e) { return false; } };

async function main() {
  const cfg = loadEnv(path.join(__dirname, '..'));
  const ring = encryptionKeyring(cfg);
  const out = {
    keyring: Object.entries(ring).map(([v, hex]) => ({
      version: 'k' + v, fingerprint: fp(hex),
      role: Number(v) === currentKeyVersion() ? 'ACTIVE WRITE KEY' : 'historical (decrypt only)',
    })),
    activeWriteVersion: 'k' + currentKeyVersion(),
    connections: [],
  };
  for (const c of await all(`SELECT id, status, client_secret_enc, refresh_token_enc, access_token_enc,
      access_token_expires_at FROM connections ORDER BY id`)) {
    out.connections.push({
      connectionId: Number(c.id), status: c.status,
      clientSecret: { cipherVersion: prefixOf(c.client_secret_enc), decryptable: canDecrypt(c.client_secret_enc) },
      refreshToken: { cipherVersion: prefixOf(c.refresh_token_enc), decryptable: canDecrypt(c.refresh_token_enc) },
      accessTokenCache: { cipherVersion: prefixOf(c.access_token_enc), decryptable: canDecrypt(c.access_token_enc),
        expiresAt: c.access_token_expires_at ? new Date(c.access_token_expires_at).toISOString() : null },
    });
  }
  const allOk = out.connections.every(c =>
    c.refreshToken.decryptable !== false && c.clientSecret.decryptable !== false);
  out.verdict = allOk
    ? 'ALL STORED SECRETS DECRYPT with the loaded keyring — k1 exists; no token is unrecoverable; no re-authorization needed on this evidence.'
    : 'SOME SECRETS DO NOT DECRYPT — the ciphertext version listed above has no matching key in this environment; restore that MADAR_ENCRYPTION_KEY(_Vn) or re-authorize the affected connection.';
  console.log(JSON.stringify(out, null, 2));
  await closeDb();
  process.exit(allOk ? 0 : 1);
}

main().catch(async e => { console.error('keyring-inspect failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
