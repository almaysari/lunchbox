// PostgreSQL is Madar's primary and only runtime database — development,
// live mode, production and integration tests all run on it.
// (SQLite was removed from the runtime path entirely; see docs/DECISIONS.md.)
const path = require('path');
const { Pool } = require('pg');

let pool = null;

function getPool() {
  if (pool) return pool;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is required (e.g. postgresql://madar:***@localhost:5432/madar)');
  pool = new Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX || 10) });
  pool.on('error', err => console.error('[madar] pg pool error:', err.message));
  return pool;
}

// helpers — always parameterized
const q = (text, params = []) => getPool().query(text, params);
const all = async (text, params = []) => (await q(text, params)).rows;
const one = async (text, params = []) => (await q(text, params)).rows[0] || null;
const run = async (text, params = []) => (await q(text, params)).rowCount;

async function tx(fn) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function healthy() {
  try { await q('SELECT 1'); return true; } catch { return false; }
}

async function closeDb() { if (pool) { await pool.end(); pool = null; } }

// Attachment files live OUTSIDE public/, under a data dir (never served statically).
const DATA_DIR = process.env.MADAR_DATA_DIR || path.join(__dirname, '..', 'data');
const ATTACH_DIR = process.env.MADAR_ATTACH_DIR || path.join(DATA_DIR, 'attachments');

module.exports = { getPool, q, all, one, run, tx, healthy, closeDb, DATA_DIR, ATTACH_DIR };
