// Storage Provider Contract — every backend implements exactly:
//   putObject(buffer)                 -> { key, sha256, size }
//   getObject(key, {start,end}?)      -> ReadableStream (Range support)
//   deleteObject(key)                 -> void
//   exists(key)                       -> boolean
//   metadata(key)                     -> { size, createdAt } | null
//   signedUrl(key, ttlSeconds)        -> string | null (null = unsupported)
// Rules: files live OUTSIDE public/, opaque unguessable keys, size limit,
// path traversal guard, sha256 recorded. S3 adapter: core/storage-s3.js.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class LocalStorage {
  constructor(rootDir, { maxBytes }) {
    this.root = rootDir;
    this.maxBytes = maxBytes;
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
  }

  _resolve(key) {
    if (!/^[0-9a-f]{48}$/.test(String(key))) throw new Error('Invalid storage key');
    const full = path.join(this.root, key.slice(0, 2), key);
    if (!full.startsWith(this.root + path.sep)) throw new Error('Path traversal blocked');
    return full;
  }

  putObject(buffer) {
    if (!Buffer.isBuffer(buffer)) throw new Error('putObject() expects a Buffer');
    if (buffer.length > this.maxBytes) {
      throw new Error(`Attachment exceeds size limit (${buffer.length} > ${this.maxBytes} bytes)`);
    }
    const key = crypto.randomBytes(24).toString('hex');
    const full = this._resolve(key);
    fs.mkdirSync(path.dirname(full), { recursive: true, mode: 0o700 });
    fs.writeFileSync(full, buffer, { mode: 0o600 });
    return { key, sha256: crypto.createHash('sha256').update(buffer).digest('hex'), size: buffer.length };
  }

  getObject(key, range) {
    const opts = range ? { start: range.start, end: range.end } : undefined;
    return fs.createReadStream(this._resolve(key), opts);
  }

  deleteObject(key) { try { fs.unlinkSync(this._resolve(key)); } catch {} }
  exists(key) { try { return fs.existsSync(this._resolve(key)); } catch { return false; } }
  metadata(key) {
    try { const st = fs.statSync(this._resolve(key)); return { size: st.size, createdAt: st.birthtime }; }
    catch { return null; }
  }
  signedUrl() { return null; } // local backend streams via the authorized API route only

  // legacy aliases used by earlier code/tests
  put(buffer) { return this.putObject(buffer); }
  getStream(key, range) { return this.getObject(key, range); }
}

let instance = null;
function getStorage() {
  if (instance) return instance;
  const backend = process.env.MADAR_STORAGE || 'local';
  const { ATTACH_DIR } = require('./db');
  const maxBytes = Number(process.env.MAX_ATTACHMENT_MB || 25) * 1024 * 1024;
  if (backend === 'local') instance = new LocalStorage(ATTACH_DIR, { maxBytes });
  else if (backend === 's3') instance = new (require('./storage-s3').S3Storage)({ maxBytes });
  else throw new Error(`Unknown storage backend "${backend}"`);
  return instance;
}

// ---- MIME detection by magic bytes — provider MIME is NEVER trusted ----
const SIGNATURES = [
  { mime: 'application/pdf', test: b => b.slice(0, 5).toString('latin1') === '%PDF-' },
  { mime: 'image/png', test: b => b.readUInt32BE(0) === 0x89504e47 },
  { mime: 'image/jpeg', test: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { mime: 'image/gif', test: b => b.slice(0, 3).toString('latin1') === 'GIF' },
  // zip container: docx/xlsx/pptx/plain zip — reported as zip (safe generic)
  { mime: 'application/zip', test: b => b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5 || b[2] === 7) },
  // legacy MS Office (CFBF)
  { mime: 'application/msword', test: b => b.readUInt32BE(0) === 0xd0cf11e0 },
];

function detectMime(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) return 'application/octet-stream';
  for (const s of SIGNATURES) { try { if (s.test(buffer)) return s.mime; } catch {} }
  // printable text heuristic
  const sample = buffer.slice(0, 512);
  const printable = sample.every(b => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 128);
  return printable ? 'text/plain' : 'application/octet-stream';
}

function sanitizeFilename(name) {
  const base = String(name || 'attachment').split(/[\\/]/).pop();
  return base.replace(/[^\w.؀-ۿ -]+/g, '_').replace(/^\.+/, '_').slice(0, 120) || 'attachment';
}

module.exports = { getStorage, LocalStorage, detectMime, sanitizeFilename };
