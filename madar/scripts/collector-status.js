#!/usr/bin/env node
// Collector monitoring from the durable ledger — CLI companion to the
// live-sync status endpoint's `collector` section.
//
//   docker compose exec app node scripts/collector-status.js
//
// Prints, per collector mailbox: processed / unknown / retrying / failed,
// approximate Inbox backlog, move backlog (pending/done/unsupported), average
// processing latency (last 24h), oldest unprocessed age, and the write
// capability (untested / unsupported:<reason>) — everything derives from
// collector_ingest, so it is valid across restarts and from any process.
require('../core/bootstrap').initCryptoFromEnv();
const { closeDb } = require('../core/db');

(async () => {
  const collector = require('../modules/mail/collector');
  const st = await collector.status();
  if (!st.enabled) {
    console.log('collector disabled — set MADAR_COLLECTOR_ADDRESSES in .env and rebuild');
  } else {
    console.log(JSON.stringify(st, null, 2));
  }
  await closeDb();
  process.exit(0);
})().catch(async e => { console.error('collector-status failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
