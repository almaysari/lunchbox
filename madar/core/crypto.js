// Crypto core:
//  * AES-256-GCM at-rest encryption with KEY VERSIONING (rotation-ready)
//  * scrypt password hashing (explicit strong parameters)
//  * HMAC session-cookie signing and CSRF tokens (independent secrets)
//
// What is stored how (see docs/DECISIONS.md):
//  * client_id       — plaintext (public identifier, not a secret)
//  * client_secret   — AES-256-GCM at rest (versioned)
//  * refresh_token   — AES-256-GCM at rest (versioned)
//  * access_token    — NEVER persisted; process memory only, short-lived
const crypto = require('crypto');

let KEYS = {};            // version -> derived 32-byte key
let CURRENT_VERSION = 1;
let SESSION_KEY = null;
let CSRF_KEY = null;

// keyring: { 1: hex, 2: hex, ... } — highest version is used for new writes.
function init(keyring, sessionSecretHex, csrfSecretHex) {
  if (!keyring || !Object.keys(keyring).length) throw new Error('encryption keyring required');
  if (!sessionSecretHex || !csrfSecretHex) throw new Error('MADAR_SESSION_SECRET and MADAR_CSRF_SECRET are required');
  KEYS = {};
  for (const [v, hex] of Object.entries(keyring)) {
    KEYS[Number(v)] = crypto.scryptSync(Buffer.from(hex, 'hex'), 'madar-enc-v' + v, 32);
  }
  CURRENT_VERSION = Math.max(...Object.keys(KEYS).map(Number));
  SESSION_KEY = crypto.scryptSync(Buffer.from(sessionSecretHex, 'hex'), 'madar-sess-v1', 32);
  CSRF_KEY = crypto.scryptSync(Buffer.from(csrfSecretHex, 'hex'), 'madar-csrf-v1', 32);
}

function currentKeyVersion() { return CURRENT_VERSION; }

// ciphertext embeds its key version: k<ver>:iv:tag:data
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEYS[CURRENT_VERSION], iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return [`k${CURRENT_VERSION}`, iv.toString('hex'), cipher.getAuthTag().toString('hex'), enc.toString('hex')].join(':');
}

function decrypt(stored) {
  const [vTag, ivHex, tagHex, dataHex] = String(stored).split(':');
  const version = vTag === 'v1' ? 1 : Number((vTag.match(/^k(\d+)$/) || [])[1]); // 'v1' = legacy prefix
  const key = KEYS[version];
  if (!key) throw new Error(`No encryption key for version ${vTag} — add it to the keyring (key rotation)`);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}

// Rotation: re-encrypt a stored value under the newest key.
function reencrypt(stored) { return encrypt(decrypt(stored)); }

const SCRYPT_OPTS = { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64, SCRYPT_OPTS).toString('hex');
  return `scrypt$${SCRYPT_OPTS.N}$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return false;
  const [, n, salt, hash] = parts;
  const candidate = crypto.scryptSync(password, salt, 64, { ...SCRYPT_OPTS, N: Number(n) });
  return crypto.timingSafeEqual(candidate, Buffer.from(hash, 'hex'));
}

function randomToken() { return crypto.randomBytes(32).toString('hex'); }

function hmac(key, value) { return crypto.createHmac('sha256', key).update(value).digest('hex'); }

function signSession(token) { return token + '.' + hmac(SESSION_KEY, token); }

function verifySessionCookie(cookieValue) {
  const [token, sig] = String(cookieValue || '').split('.');
  if (!token || !sig) return null;
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(hmac(SESSION_KEY, token), 'hex')) ? token : null;
  } catch { return null; }
}

// CSRF: double-submit token bound to the session token.
function csrfTokenFor(sessionToken) { return hmac(CSRF_KEY, 'csrf:' + sessionToken); }
function verifyCsrf(sessionToken, headerValue) {
  if (!sessionToken || !headerValue) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(String(headerValue), 'hex'), Buffer.from(csrfTokenFor(sessionToken), 'hex'));
  } catch { return false; }
}

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

module.exports = {
  init, encrypt, decrypt, reencrypt, currentKeyVersion,
  hashPassword, verifyPassword, randomToken,
  signSession, verifySessionCookie, csrfTokenFor, verifyCsrf, sha256,
};
