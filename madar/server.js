#!/usr/bin/env node
// Madar — unified company platform. Mail is the first module.
// Zero external dependencies; Node.js >= 22 (run with --experimental-sqlite).
const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadEnv } = require('./core/env');

const cfg = loadEnv(__dirname);
// Demo data NEVER mixes with live data: demo mode gets its own database
// directory, so mock-discovered mailboxes can never leak into a live registry.
if (cfg.MODE === 'demo' && !process.env.MADAR_DATA_DIR) {
  process.env.MADAR_DATA_DIR = path.join(__dirname, 'data-demo');
}

const cryptoCore = require('./core/crypto');
const { getDb } = require('./core/db');
const auth = require('./core/auth');
const { audit, recentAudit } = require('./core/audit');
const mailRoutes = require('./modules/mail/routes');
if (!cfg.MADAR_SECRET) {
  if (cfg.MODE === 'demo') {
    cfg.MADAR_SECRET = 'demo-secret-not-for-production';
  } else {
    console.error('MADAR_SECRET is required in .env for live mode.');
    process.exit(1);
  }
}
cryptoCore.init(cfg.MADAR_SECRET);
getDb();
auth.bootstrapAdmin(cfg);

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const buf = Buffer.concat(chunks);
  const ct = String(req.headers['content-type'] || '');
  if (ct.includes('application/json')) {
    try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { return {}; }
  }
  return buf; // raw (e.g. archive ZIP upload)
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname;
  const send = (status, body, type = 'application/json; charset=utf-8') => {
    res.writeHead(status, { 'Content-Type': type });
    res.end(type.startsWith('application/json') ? JSON.stringify(body) : body);
    return true;
  };

  try {
    if (p === '/' || p === '/index.html') {
      return send(200, fs.readFileSync(path.join(__dirname, 'public', 'index.html')), 'text/html; charset=utf-8');
    }

    const cookies = parseCookies(req);
    const user = auth.userForToken(cookies.madar_session);
    const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await readBody(req) : {};

    // ---------- auth ----------
    if (p === '/api/auth/login' && req.method === 'POST') {
      const result = auth.login(body.email, body.password);
      if (!result) { audit(null, 'auth.login.failed', body.email || ''); return send(401, { error: 'بيانات الدخول غير صحيحة' }); }
      audit(result.user.id, 'auth.login', result.user.email);
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': `madar_session=${result.token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200`,
      });
      res.end(JSON.stringify(result.user));
      return;
    }
    if (p === '/api/auth/logout' && req.method === 'POST') {
      auth.logout(cookies.madar_session);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'madar_session=; Path=/; Max-Age=0' });
      res.end('{}');
      return;
    }
    if (p === '/api/auth/me') return send(200, user || null);

    // Everything below requires a signed-in user.
    if (!user) return send(401, { error: 'unauthenticated' });
    const requireAdmin = () => {
      if (user.role === 'admin') return true;
      send(403, { error: 'admin only' });
      return false;
    };

    // ---------- platform admin ----------
    if (p === '/api/admin/users' && req.method === 'GET') {
      if (!requireAdmin()) return;
      return send(200, auth.listUsers().map(u => ({ ...u, grants: auth.grantsForUser(u.id) })));
    }
    if (p === '/api/admin/users' && req.method === 'POST') {
      if (!requireAdmin()) return;
      if (!body.email || !body.password) return send(400, { error: 'email and password required' });
      const id = auth.createUser(body);
      audit(user.id, 'admin.user.create', body.email);
      return send(200, { id });
    }
    if (p === '/api/admin/grants' && req.method === 'POST') {
      if (!requireAdmin()) return;
      auth.setGrant(Number(body.user_id), Number(body.mailbox_id), body.permission || null);
      audit(user.id, 'admin.grant.set', `user:${body.user_id} mailbox:${body.mailbox_id}`, body.permission || 'revoked');
      return send(200, { ok: true });
    }
    if (p === '/api/admin/audit' && req.method === 'GET') {
      if (!requireAdmin()) return;
      return send(200, recentAudit(300));
    }
    if (p === '/api/status') {
      return send(200, { mode: cfg.MODE, user, mailboxes: getDb().prepare('SELECT COUNT(*) n FROM mailboxes').get().n });
    }

    // ---------- mail module ----------
    const handled = await mailRoutes.handle(req, res, url, user, body, { send, requireAdmin, baseUrl: cfg.BASE_URL });
    if (handled) return;

    return send(404, { error: 'not found' });
  } catch (err) {
    console.error(err);
    return send(500, { error: String(err.message || err) });
  }
});

async function start() {
  if (cfg.MODE === 'demo') {
    // Demo: in-process mock of the Zoho API serving the company fixture
    // (20 shared mailboxes across two domains) so the whole flow —
    // connect → discover → compare → pilot → sync — can be exercised safely.
    const { startMockZoho } = require('./test/mock-zoho');
    const mockPort = await startMockZoho(0);
    const { seedDemoConnection } = require('./test/demo-seed');
    await seedDemoConnection(`http://127.0.0.1:${mockPort}`);
    console.log(`[madar] Demo mode: mock Zoho API on port ${mockPort}`);
  }
  server.listen(cfg.PORT, () => {
    console.log(`[madar] running on http://localhost:${cfg.PORT} (mode: ${cfg.MODE})`);
  });
  if (cfg.SYNC_INTERVAL_MINUTES > 0) {
    // Scheduled incremental sync runs ONLY for pilot mailboxes whose first
    // sync was explicitly started by an admin from the UI (sync_enabled=1).
    setInterval(async () => {
      const pilots = getDb().prepare("SELECT id, address FROM mailboxes WHERE is_pilot=1 AND sync_enabled=1 AND strategy='mail_api'").all();
      for (const mb of pilots) {
        try { await require('./modules/mail/sync').syncMailbox(mb.id); }
        catch (e) { console.error('[madar] scheduled sync failed for', mb.address, e.message); }
      }
    }, cfg.SYNC_INTERVAL_MINUTES * 60 * 1000);
  }
}

start();
