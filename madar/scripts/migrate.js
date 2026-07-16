#!/usr/bin/env node
// Migration runner: applies migrations/*.sql in order, each inside its own
// transaction, recording history in schema_migrations. Forward-only strategy
// (see docs/DECISIONS.md): never edit an applied migration — add a new one.
const fs = require('fs');
const path = require('path');
const { loadEnv } = require('../core/env');
loadEnv(path.join(__dirname, '..'));
const { getPool, closeDb } = require('../core/db');

async function main() {
  const pool = getPool();
  await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);

  const dir = path.join(__dirname, '..', 'migrations');
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.sql')).sort();
  const { createHash } = require('crypto');
  let applied = 0;

  for (const file of files) {
    const sql = fs.readFileSync(path.join(dir, file), 'utf8');
    const checksum = createHash('sha256').update(sql).digest('hex');
    const row = (await pool.query('SELECT checksum FROM schema_migrations WHERE name = $1', [file])).rows[0];
    if (row) {
      if (row.checksum !== checksum) {
        throw new Error(`Migration ${file} was modified after being applied (checksum mismatch). ` +
          'Migrations are forward-only: add a new migration instead of editing an applied one.');
      }
      continue;
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [file, checksum]);
      await client.query('COMMIT');
      console.log('applied:', file);
      applied++;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw new Error(`Migration ${file} failed and was rolled back: ${err.message}`);
    } finally {
      client.release();
    }
  }
  console.log(applied ? `done (${applied} new)` : 'up to date');
  await closeDb();
}

main().catch(err => { console.error(err.message); process.exit(1); });
