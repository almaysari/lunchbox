#!/usr/bin/env node
// People Desk — HR CV inbox platform backed by Zoho Mail API.
// Zero external dependencies; Node.js >= 18.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadEnv } = require('./lib/env');
const { loadDb, saveDb, CV_DIR } = require('./lib/store');
const { ZohoClient, SCOPES } = require('./lib/zoho');
const { syncOnce } = require('./lib/sync');
const { seedDemo } = require('./lib/demo');

const cfg = loadEnv(__dirname);
const zoho = new ZohoClient(cfg);

if (cfg.MODE === 'demo') seedDemo();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.svg': 'image/svg+xml',
};

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type });
  res.end(type.startsWith('application/json') ? JSON.stringify(body) : body);
}

let syncing = false;
async function runSync() {
  if (cfg.MODE === 'demo') return { mode: 'demo', note: 'Demo mode: sync is simulated.' };
  if (syncing) return { note: 'Sync already in progress.' };
  syncing = true;
  try {
    return await syncOnce(zoho, cfg);
  } catch (err) {
    const db = loadDb();
    db.lastSyncError = String(err.message || err);
    saveDb(db);
    throw err;
  } finally {
    syncing = false;
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname;

  try {
    if (p === '/' || p === '/index.html') {
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', 'index.html')), MIME['.html']);
    }

    if (p === '/api/status') {
      const db = loadDb();
      return send(res, 200, {
        mode: cfg.MODE,
        connected: cfg.MODE === 'demo' ? false : zoho.hasConnection(),
        configured: Boolean(cfg.ZOHO_CLIENT_ID && cfg.ZOHO_CLIENT_SECRET),
        mailbox: cfg.ZOHO_MAILBOX || null,
        candidates: db.candidates.length,
        lastSync: db.lastSync,
        lastSyncError: db.lastSyncError,
        syncing,
      });
    }

    if (p === '/api/candidates') {
      const db = loadDb();
      const q = (url.searchParams.get('q') || '').toLowerCase();
      let list = db.candidates;
      if (q) {
        list = list.filter(c =>
          [c.fromName, c.from, c.subject, c.summary, ...(c.attachments || []).map(a => a.name)]
            .join(' ').toLowerCase().includes(q));
      }
      return send(res, 200, list);
    }

    if (p.startsWith('/api/candidates/') && p.endsWith('/status') && req.method === 'POST') {
      const id = decodeURIComponent(p.split('/')[3]);
      let body = '';
      for await (const chunk of req) body += chunk;
      const { status } = JSON.parse(body || '{}');
      if (!['new', 'reviewed', 'shortlisted', 'rejected'].includes(status)) {
        return send(res, 400, { error: 'invalid status' });
      }
      const db = loadDb();
      const cand = db.candidates.find(c => c.id === id);
      if (!cand) return send(res, 404, { error: 'not found' });
      cand.status = status;
      saveDb(db);
      return send(res, 200, cand);
    }

    if (p.startsWith('/cv/')) {
      const file = path.basename(decodeURIComponent(p.slice(4))); // basename => no traversal
      const full = path.join(CV_DIR, file);
      if (!fs.existsSync(full)) return send(res, 404, { error: 'file not found' });
      const ext = path.extname(full).toLowerCase();
      res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Content-Disposition': `inline; filename="${encodeURIComponent(file)}"`,
      });
      return fs.createReadStream(full).pipe(res);
    }

    if (p === '/api/sync' && req.method === 'POST') {
      const result = await runSync();
      return send(res, 200, result);
    }

    if (p === '/api/oauth/url') {
      if (!cfg.ZOHO_CLIENT_ID) return send(res, 400, { error: 'ZOHO_CLIENT_ID is not set in .env' });
      return send(res, 200, { url: zoho.authorizeUrl(), scopes: SCOPES });
    }

    if (p === '/oauth/callback') {
      const code = url.searchParams.get('code');
      if (!code) return send(res, 400, 'Missing ?code', 'text/plain');
      await zoho.exchangeCode(code);
      res.writeHead(302, { Location: '/?connected=1' });
      return res.end();
    }

    return send(res, 404, { error: 'not found' });
  } catch (err) {
    console.error(err);
    return send(res, 500, { error: String(err.message || err) });
  }
});

server.listen(cfg.PORT, () => {
  console.log(`People Desk running on http://localhost:${cfg.PORT} (mode: ${cfg.MODE})`);
  if (cfg.MODE === 'live' && cfg.SYNC_INTERVAL_MINUTES > 0) {
    setInterval(() => runSync().catch(e => console.error('scheduled sync failed:', e.message)),
      cfg.SYNC_INTERVAL_MINUTES * 60 * 1000);
  }
});
