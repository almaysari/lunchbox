// AES-256-GCM encryption for stored secrets (OAuth tokens, client secrets),
// scrypt password hashing, and HMAC session-cookie signing.
// Two independent secrets (validated in core/env.js):
//   MADAR_ENCRYPTION_KEY — encrypts data at rest
//   MADAR_SESSION_SECRET — signs session cookies
const crypto = require('crypto');

let ENC_KEY = null;
let SESSION_KEY = null;

function init(encryptionKeyHex, sessionSecretHex) {
  if (!encryptionKeyHex || !sessionSecretHex) throw new Error('Both MADAR_ENCRYPTION_KEY and MADAR_SESSION_SECRET are required.');
  ENC_KEY = crypto.scryptSync(Buffer.from(encryptionKeyHex, 'hex'), 'madar-enc-v1', 32);
  SESSION_KEY = crypto.scryptSync(Buffer.from(sessionSecretHex, 'hex'), 'madar-sess-v1', 32);
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return ['v1', iv.toString('hex'), cipher.getAuthTag().toString('hex'), enc.toString('hex')].join(':');
}

function decrypt(stored) {
  const [v, ivHex, tagHex, dataHex] = String(stored).split(':');
  if (v !== 'v1') throw new Error('Unknown ciphertext version');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}

// scrypt with explicit strong parameters (N=2^15, r=8, p=1)
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

// Session cookie value: token.signature — tampering invalidates it.
function signSession(token) {
  const sig = crypto.createHmac('sha256', SESSION_KEY).update(token).digest('hex');
  return token + '.' + sig;
}

function verifySessionCookie(cookieValue) {
  const [token, sig] = String(cookieValue || '').split('.');
  if (!token || !sig) return null;
  const expected = crypto.createHmac('sha256', SESSION_KEY).update(token).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex')) ? token : null;
  } catch { return null; }
}

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

module.exports = { init, encrypt, decrypt, hashPassword, verifyPassword, randomToken, signSession, verifySessionCookie, sha256 };
