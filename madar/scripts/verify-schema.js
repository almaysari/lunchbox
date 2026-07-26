#!/usr/bin/env node
// verify:schema — regenerates the schema dump from the LIVE database and
// fails (exit 1) if docs/POSTGRES-SCHEMA-VERIFIED.md no longer matches.
// Pass --update to rewrite the doc instead of failing.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { loadEnv } = require('../core/env');
loadEnv(path.join(__dirname, '..'));

const DOC = path.join(__dirname, '..', 'docs', 'POSTGRES-SCHEMA-VERIFIED.md');
const url = new URL(process.env.DATABASE_URL);

function dumpSchema() {
  const out = execFileSync('pg_dump', [
    '--schema-only', '--no-owner', '--no-privileges',
    '-h', url.hostname, '-p', url.port || '5432', '-U', url.username, '-d', url.pathname.slice(1),
  ], { encoding: 'utf8', env: { ...process.env, PGPASSWORD: decodeURIComponent(url.password) } });
  return out.split('\n')
    .filter(l => !/^(--|SET |SELECT pg_catalog|\\)/.test(l))
    .join('\n').replace(/\n{3,}/g, '\n\n').trim();
}

function render(sqlBody) {
  return `# PostgreSQL Schema — Verified (extracted from a live database)

> يُولَّد هذا الملف حصريًا بـ \`npm run verify:schema -- --update\` — لا يُحرر يدويًا.
> \`npm run verify:schema\` يفشل إذا اختلف الـSchema الفعلي عن هذا الملف (يعمل في CI).

## الجداول والأعمدة والقيود (pg_dump --schema-only)

\`\`\`sql
${sqlBody}
\`\`\`
`;
}

const fresh = render(dumpSchema());
if (process.argv.includes('--update')) {
  fs.writeFileSync(DOC, fresh);
  console.log('schema doc updated:', DOC);
} else {
  const current = fs.existsSync(DOC) ? fs.readFileSync(DOC, 'utf8') : '';
  if (current.trim() === fresh.trim()) {
    console.log('verify:schema OK — docs match the live database schema');
  } else {
    console.error('verify:schema FAILED — docs/POSTGRES-SCHEMA-VERIFIED.md is stale.');
    console.error('Run: npm run migrate && npm run verify:schema -- --update');
    process.exit(1);
  }
}
