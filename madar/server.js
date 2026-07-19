#!/usr/bin/env node
// Madar — unified company platform. Mail is the first module.
// Runtime database: PostgreSQL (all modes). Node.js >= 20.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadEnv, validateSecrets, encryptionKeyring } = require('./core/env');

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
if (/CHANGE_ME/i.test(cfg.DATABASE_URL)) {
  console.error('DATABASE_URL still contains a CHANGE_ME placeholder — set a real value.');
  process.exit(1);
}
if (cfg.MODE === 'demo' && !process.env.MADAR_MAX_RPM) process.env.MADAR_MAX_RPM = '100000';

const cryptoCore = require('./core/crypto');
cryptoCore.init(encryptionKeyring(cfg), cfg.MADAR_SESSION_SECRET, cfg.MADAR_CSRF_SECRET);
const db = require('./core/db');
const auth = require('./core/auth');
const { audit, recentAudit } = require('./core/audit');
const mailRoutes = require('./modules/mail/routes');

const SECURE_COOKIES = cfg.BASE_URL.startsWith('https://');
const cookieFlags = `HttpOnly; Path=/; SameSite=Lax${SECURE_COOKIES ? '; Secure' : ''}`;

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

// Uploads (eDiscovery ZIP parts) are buffered in memory — enforce an explicit
// cap with a clear 413 instead of letting a multi-GB body exhaust the process.
const MAX_BODY_BYTES = (Number(process.env.MADAR_MAX_UPLOAD_MB) || 1024) * 1024 * 1024;

async function readBody(req) {
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > MAX_BODY_BYTES) { const e = new Error('payload too large'); e.tooLarge = true; throw e; }
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY_BYTES) { const e = new Error('payload too large'); e.tooLarge = true; throw e; }
    chunks.push(c);
  }
  const buf = Buffer.concat(chunks);
  const ct = String(req.headers['content-type'] || '');
  if (ct.includes('application/json')) {
    try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { return {}; }
  }
  return buf;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname;
  const extraCookies = [];
  const send = (status, body, type = 'application/json; charset=utf-8') => {
    const headers = { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff' };
    if (extraCookies.length) headers['Set-Cookie'] = extraCookies;
    res.writeHead(status, headers);
    res.end(type.startsWith('application/json') ? JSON.stringify(body) : body);
    return true;
  };

  try {
    // liveness: process is up — touches no dependency
    if (p === '/health/live') return send(200, { status: 'alive' });
    // readiness: db + migrations + storage + encryption (details are booleans only)
    if (p === '/health/ready' || p === '/healthz') {
      const { readiness } = require('./core/health');
      const r = await readiness({
        db, storageDir: db.ATTACH_DIR, cryptoReady: true,
        migrationsDir: path.join(__dirname, 'migrations'),
      });
      // Worker + stuck-state visibility (report-only: readiness gates HTTP
      // traffic; the background worker must be MONITORED, not used to pull the
      // whole app out of the load balancer). Numbers only — no addresses/PII.
      let worker = null;
      if (r.checks.database) {
        try { worker = await require('./modules/mail/live-sync').workerHealth(); }
        catch { worker = { running: false, error: 'worker status unavailable' }; }
      }
      return send(r.ready ? 200 : 503, { status: r.ready ? 'ready' : 'not_ready', checks: r.checks, worker });
    }
    if (p === '/' || p === '/index.html') {
      return send(200, fs.readFileSync(path.join(__dirname, 'public', 'index.html')), 'text/html; charset=utf-8');
    }

    const cookies = parseCookies(req);
    const sessionToken = cryptoCore.verifySessionCookie(cookies.madar_session);
    const { user, rotatedToken } = await auth.userForToken(sessionToken);
    const activeToken = rotatedToken || sessionToken;
    if (rotatedToken) {
      extraCookies.push(`madar_session=${cryptoCore.signSession(rotatedToken)}; ${cookieFlags}; Max-Age=43200`);
    }
    let body = {};
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      try { body = await readBody(req); }
      catch (e) {
        if (!e.tooLarge) throw e;
        return send(413, { error: `الملف أكبر من الحد المسموح (${Math.round(MAX_BODY_BYTES / 1024 / 1024)}MB) — قسّم تصدير eDiscovery إلى أجزاء أصغر (مثلًا بنطاقات زمنية) وارفعها معًا، أو ارفع MADAR_MAX_UPLOAD_MB` });
      }
    }

    // ---------- auth ----------
    if (p === '/api/auth/login' && req.method === 'POST') {
      const result = await auth.login(body.email, body.password);
      if (result && result.locked) {
        await audit(null, 'auth.login.locked', body.email || '');
        return send(429, { error: 'تم إيقاف تسجيل الدخول مؤقتًا بعد محاولات فاشلة متكررة — حاول بعد 15 دقيقة' });
      }
      if (!result) { await audit(null, 'auth.login.failed', String(body.email || '').toLowerCase().trim()); return send(401, { error: 'بيانات الدخول غير صحيحة' }); }
      await audit(result.user.id, 'auth.login', result.user.email);
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': [`madar_session=${cryptoCore.signSession(result.token)}; ${cookieFlags}; Max-Age=43200`],
      });
      res.end(JSON.stringify({ ...result.user, csrf: cryptoCore.csrfTokenFor(result.token) }));
      return;
    }
    if (p === '/api/auth/logout' && req.method === 'POST') {
      await auth.logout(activeToken);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `madar_session=; Path=/; Max-Age=0` });
      res.end('{}');
      return;
    }
    if (p === '/api/auth/setup-status') {
      const n = await db.one('SELECT COUNT(*)::int AS n FROM users');
      return send(200, { hasUsers: n.n > 0 }); // nothing sensitive — login-screen hint only
    }
    if (p === '/api/auth/me') {
      return send(200, user ? { ...user, csrf: cryptoCore.csrfTokenFor(activeToken) } : null);
    }

    if (!user) return send(401, { error: 'unauthenticated' });

    // First-login policy: initial credentials must be changed before anything else.
    if (user.mustChangePassword && !['/api/auth/change-password', '/api/auth/logout', '/api/auth/me'].includes(p)) {
      return send(428, { error: 'password change required', code: 'MUST_CHANGE_PASSWORD' });
    }

    // ---------- CSRF: every mutating request needs the header ----------
    // Defense-in-depth: session-bound HMAC token (NOT plain double-submit) on
    // every mutating request; SameSite=Lax is a second layer, not the only one.
    // /oauth/callback needs no exemption: it is GET-only and guarded by the
    // one-time hashed state in oauth_states.
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      if (!cryptoCore.verifyCsrf(activeToken, req.headers['x-csrf-token'])) {
        await audit(user.id, 'security.csrf_rejected', p);
        return send(403, { error: 'CSRF token missing or invalid' });
      }
    }

    if (p === '/api/auth/change-password' && req.method === 'POST') {
      try {
        await auth.changeOwnPassword(user.id, body.current_password, body.new_password);
      } catch (err) { return send(400, { error: String(err.message) }); }
      await audit(user.id, 'auth.password.changed', user.email); // passwords never logged
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'madar_session=; Path=/; Max-Age=0' });
      res.end(JSON.stringify({ ok: true, note: 'all sessions revoked — sign in again' }));
      return;
    }

    const requireAdmin = () => {
      if (auth.isPlatformAdmin(user)) return true;
      send(403, { error: 'platform admin role required' });
      return false;
    };

    // ---------- platform admin ----------
    if (p === '/api/admin/users' && req.method === 'GET') {
      if (!requireAdmin()) return;
      const users = await auth.listUsers();
      return send(200, await Promise.all(users.map(async u => ({
        ...u, id: Number(u.id),
        roles: await auth.rolesForUser(u.id),
        grants: await auth.grantsForUser(u.id),
      }))));
    }
    if (p === '/api/admin/users' && req.method === 'POST') {
      if (!requireAdmin()) return;
      if (!body.email || !body.password) return send(400, { error: 'email and password required' });
      const id = await auth.createUser(body);
      await audit(user.id, 'admin.user.create', body.email, { roles: body.roles || ['member'] });
      return send(200, { id });
    }
    if (p === '/api/admin/roles' && req.method === 'GET') {
      if (!requireAdmin()) return;
      return send(200, await db.all('SELECT * FROM roles ORDER BY id'));
    }
    if (p === '/api/admin/user-roles' && req.method === 'POST') {
      if (!requireAdmin()) return;
      if (body.assign) await auth.assignRole(Number(body.user_id), body.assign);
      if (body.revoke) await auth.revokeRole(Number(body.user_id), body.revoke);
      await audit(user.id, 'admin.role.change', 'user:' + body.user_id, { assign: body.assign, revoke: body.revoke });
      return send(200, { ok: true });
    }
    if (p === '/api/admin/grants' && req.method === 'POST') {
      if (!requireAdmin()) return;
      await auth.setGrant(Number(body.user_id), Number(body.mailbox_id), body.flags || null);
      await audit(user.id, 'admin.grant.set', `user:${body.user_id} mailbox:${body.mailbox_id}`, body.flags || 'revoked');
      return send(200, { ok: true });
    }
    if (p === '/api/admin/reset-password' && req.method === 'POST') {
      if (!requireAdmin()) return;
      await auth.resetPassword(Number(body.user_id), body.new_password);
      await audit(user.id, 'admin.password.reset', 'user:' + body.user_id); // password itself never logged
      return send(200, { ok: true, note: 'all sessions of the user were revoked' });
    }
    if (p === '/api/admin/audit' && req.method === 'GET') {
      if (!auth.isAuditor(user)) return send(403, { error: 'auditor role required' });
      const rows = await recentAudit(300);
      return send(200, rows.map(r => ({ ...r, at: new Date(r.at).getTime() })));
    }
    if (p === '/api/status') {
      const n = await db.one('SELECT COUNT(*)::int AS n FROM mailboxes');
      return send(200, { mode: cfg.MODE, user, mailboxes: n.n });
    }

    // ---------- mail module ----------
    const handled = await mailRoutes.handle(req, res, url, user, body, { send, baseUrl: cfg.BASE_URL });
    if (handled) return;

    return send(404, { error: 'not found' });
  } catch (err) {
    // Never a bare "internal error": emit a traceable id, log the FULL stack
    // server-side, and return the real (sanitized) cause + any sync trace id so
    // the operator can open the diagnostics row.
    const errId = 'err-' + Date.now().toString(36) + '-' + Math.floor(process.hrtime()[1] % 1e6).toString(36);
    console.error(`[madar] ${errId} on ${req.method} ${p}:`, err && err.stack ? err.stack : err);
    // scrub any credential-shaped substring before it reaches the client
    const scrub = s => String(s || '').replace(/(\w+:\/\/[^:@\s]+:)[^@\s]+(@)/g, '$1***$2');
    return send(500, {
      error: scrub(err.message || err),
      errorClass: (err && err.name) || 'Error',
      errorId: errId,
      traceId: (err && err.traceId) || undefined,   // sync-cycle diagnostics id, if any
      stage: (err && err.stage) || undefined,
    });
  }
});

async function start() {
  if (!(await db.healthy())) {
    console.error('[madar] PostgreSQL is unreachable at DATABASE_URL. Start it first (docker compose up -d postgres).');
    process.exit(1);
  }
  try { require('./core/storage').getStorage(); } catch (err) {
    console.error('[madar] storage backend failed to initialize:', err.message);
    process.exit(1); // e.g. MADAR_STORAGE=s3 while the S3 adapter is not implemented
  }
  const recovered = await require('./modules/mail/sync').recoverStaleJobs();
  if (recovered.length) console.log(`[madar] recovered ${recovered.length} stale running sync job(s) → paused (resumable)`);
  if (cfg.MODE === 'demo') {
    const { startMockZoho } = require('./test/mock-zoho');
    const mockPort = await startMockZoho(0);
    const { seedDemoConnection } = require('./test/demo-seed');
    await seedDemoConnection(`http://127.0.0.1:${mockPort}`);
    console.log(`[madar] Demo mode: mock Zoho API on port ${mockPort} (results are Mock Discovery, not Zoho)`);
  }
  server.listen(cfg.PORT, () => {
    console.log(`[madar] running on http://localhost:${cfg.PORT} (mode: ${cfg.MODE}, db: postgresql)`);
  });
  // Live Sync worker: polls every admin-enabled mail_api mailbox (default 120s,
  // MADAR_LIVE_SYNC_INTERVAL_SEC), with per-mailbox backoff. MADAR_LIVE_SYNC=off disables.
  if (require('./modules/mail/live-sync').startLiveSync()) {
    console.log(`[madar] live sync worker started (every ${Math.round((Number(process.env.MADAR_LIVE_SYNC_INTERVAL_SEC) || 120))}s; per-mailbox backoff on errors)`);
  }
  // Durable acceptance sampler: if an acceptance run is active (or is started
  // later via the CLI), this supervised loop samples it — so a container
  // restart RESUMES the soak instead of killing it (state lives in PostgreSQL).
  require('./modules/mail/acceptance').startAcceptanceSampler();
}

// ---- crash-only process design: no failure mode requires a MANUAL restart ----
// Node ≥15 CRASHES the process on an unhandled promise rejection — one missed
// await anywhere would take the server AND the sync worker down. Rejections are
// logged in full (stack + errorId) and survived: every sync path already has its
// own typed error handling, so a stray rejection is a logging bug, not a reason
// to drop service. A truly uncaught EXCEPTION leaves the process in an undefined
// state — there we log everything, mark the worker heartbeat off, and exit(1):
// docker-compose's `restart: unless-stopped` relaunches us, and boot recovery
// (recoverStaleJobs + per-tick reconcileStale) resumes every in-flight job from
// its persisted cursor. Crash → automatic clean recovery, never a wedged state.
process.on('unhandledRejection', (reason) => {
  const errId = 'rej-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  console.error(`[madar] UNHANDLED REJECTION ${errId} (survived):`,
    (reason && reason.stack) || String(reason));
});
process.on('uncaughtException', (err) => {
  console.error('[madar] UNCAUGHT EXCEPTION — exiting for clean restart:', err && err.stack || err);
  const finish = () => process.exit(1);
  try {
    require('./modules/mail/live-sync').stopLiveSync(); // publishes heartbeat off
    setTimeout(finish, 1500).unref();                   // give the heartbeat write a moment
  } catch { finish(); }
});
let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return; shuttingDown = true;
  console.log(`[madar] ${signal} — graceful shutdown (worker off, drain, close db)`);
  try { require('./modules/mail/live-sync').stopLiveSync(); } catch { /* heartbeat best-effort */ }
  try { require('./modules/mail/acceptance').stopAcceptanceSampler(); } catch { /* run state is durable */ }
  server.close(async () => {
    try { await db.closeDb(); } catch { /* pool already gone */ }
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 8000).unref(); // never hang a stop/restart
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

start();
