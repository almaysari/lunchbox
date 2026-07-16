#!/usr/bin/env node
// Madar — unified company platform. Mail is the first module.
// Runtime database: PostgreSQL (all modes). Node.js >= 20.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadEnv, validateSecrets } = require('./core/env');

const cfg = loadEnv(__dirname);
const secretErrors = validateSecrets(cfg);
if (secretErrors.length) {
  console.error('Configuration errors:\n - ' + secretErrors.join('\n - '));
  process.exit(1);
}
if (!cfg.DATABASE_URL) {
  console.error('DATABASE_URL is required (PostgreSQL). See .env.example / docker-compose.yml.');
  process.exit(1);
}
// Demo talks to a local in-process mock — no rate budget needed there.
if (cfg.MODE === 'demo' && !process.env.MADAR_MAX_RPM) process.env.MADAR_MAX_RPM = '100000';

const cryptoCore = require('./core/crypto');
cryptoCore.init(cfg.MADAR_ENCRYPTION_KEY, cfg.MADAR_SESSION_SECRET);
const db = require('./core/db');
const auth = require('./core/auth');
const { audit, recentAudit } = require('./core/audit');
const mailRoutes = require('./modules/mail/routes');

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
    if (p === '/healthz') {
      const ok = await db.healthy();
      return send(ok ? 200 : 503, { status: ok ? 'ok' : 'db_unreachable' });
    }
    if (p === '/' || p === '/index.html') {
      return send(200, fs.readFileSync(path.join(__dirname, 'public', 'index.html')), 'text/html; charset=utf-8');
    }

    const cookies = parseCookies(req);
    const sessionToken = cryptoCore.verifySessionCookie(cookies.madar_session);
    const user = await auth.userForToken(sessionToken);
    const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await readBody(req) : {};

    // ---------- auth ----------
    if (p === '/api/auth/login' && req.method === 'POST') {
      const result = await auth.login(body.email, body.password);
      if (!result) { await audit(null, 'auth.login.failed', body.email || ''); return send(401, { error: 'بيانات الدخول غير صحيحة' }); }
      await audit(result.user.id, 'auth.login', result.user.email);
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': `madar_session=${cryptoCore.signSession(result.token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200`,
      });
      res.end(JSON.stringify(result.user));
      return;
    }
    if (p === '/api/auth/logout' && req.method === 'POST') {
      await auth.logout(sessionToken);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'madar_session=; Path=/; Max-Age=0' });
      res.end('{}');
      return;
    }
    if (p === '/api/auth/me') return send(200, user || null);

    if (!user) return send(401, { error: 'unauthenticated' });
    const requireAdmin = () => {
      if (user.role === 'admin') return true;
      send(403, { error: 'admin only' });
      return false;
    };

    // ---------- platform admin ----------
    if (p === '/api/admin/users' && req.method === 'GET') {
      if (!requireAdmin()) return;
      const users = await auth.listUsers();
      return send(200, await Promise.all(users.map(async u => ({ ...u, id: Number(u.id), grants: await auth.grantsForUser(u.id) }))));
    }
    if (p === '/api/admin/users' && req.method === 'POST') {
      if (!requireAdmin()) return;
      if (!body.email || !body.password) return send(400, { error: 'email and password required' });
      const id = await auth.createUser(body);
      await audit(user.id, 'admin.user.create', body.email);
      return send(200, { id });
    }
    if (p === '/api/admin/grants' && req.method === 'POST') {
      if (!requireAdmin()) return;
      await auth.setGrant(Number(body.user_id), Number(body.mailbox_id), body.permission || null);
      await audit(user.id, 'admin.grant.set', `user:${body.user_id} mailbox:${body.mailbox_id}`, body.permission || 'revoked');
      return send(200, { ok: true });
    }
    if (p === '/api/admin/audit' && req.method === 'GET') {
      if (!requireAdmin()) return;
      const rows = await recentAudit(300);
      return send(200, rows.map(r => ({ ...r, at: new Date(r.at).getTime() })));
    }
    if (p === '/api/status') {
      const n = await db.one('SELECT COUNT(*)::int AS n FROM mailboxes');
      return send(200, { mode: cfg.MODE, user, mailboxes: n.n });
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
  if (!(await db.healthy())) {
    console.error('[madar] PostgreSQL is unreachable at DATABASE_URL. Start it first (docker compose up -d postgres).');
    process.exit(1);
  }
  if (cfg.MODE === 'demo') {
    // Demo: in-process mock Zoho API + mock-discovered registry, in a demo DATABASE.
    // Point DATABASE_URL at a dedicated demo database — never the live one.
    const { startMockZoho } = require('./test/mock-zoho');
    const mockPort = await startMockZoho(0);
    const { seedDemoConnection } = require('./test/demo-seed');
    await seedDemoConnection(`http://127.0.0.1:${mockPort}`);
    console.log(`[madar] Demo mode: mock Zoho API on port ${mockPort} (results are Mock Discovery, not Zoho)`);
  }
  server.listen(cfg.PORT, () => {
    console.log(`[madar] running on http://localhost:${cfg.PORT} (mode: ${cfg.MODE}, db: postgresql)`);
  });
  if (cfg.SYNC_INTERVAL_MINUTES > 0) {
    // Scheduled incremental sync ONLY for pilot mailboxes explicitly started by an admin.
    setInterval(async () => {
      const pilots = await db.all("SELECT id, address FROM mailboxes WHERE is_pilot AND sync_enabled AND strategy = 'mail_api'");
      for (const mb of pilots) {
        try { await require('./modules/mail/sync').syncMailbox(Number(mb.id)); }
        catch (e) { console.error('[madar] scheduled sync failed for', mb.address, e.message); }
      }
    }, cfg.SYNC_INTERVAL_MINUTES * 60 * 1000);
  }
}

start();
