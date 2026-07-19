// Low-level Zoho Mail API client bound to an organization connection.
// Every call returns { url, status, body } WITHOUT throwing on HTTP errors —
// the detection engine needs literal API responses as evidence.
// Docs: https://www.zoho.com/mail/help/api/
const crypto = require('crypto');
const { one, q } = require('../../core/db');
const { decrypt, encrypt } = require('../../core/crypto');

// Typed OAuth-phase error: token acquisition failures must NEVER be reported as
// transport ("HTTP 0") — they happen BEFORE any request leaves the process.
// (Proven root-cause candidate: the old get() had one catch around token()+fetch,
// so a refresh rejection or an undecryptable secret masqueraded as HTTP 0 even
// with a perfectly healthy network.)
class ZohoAuthError extends Error {
  constructor(classification, message, extra = {}) {
    super(message);
    this.name = 'ZohoAuthError';
    this.classification = classification; // oauth_token_missing | oauth_token_decrypt_failed | oauth_refresh_failed
    Object.assign(this, extra);           // e.g. { zohoError, httpStatus }
  }
}

// Non-reversible token identifier for evidence: hash prefix only, never the value.
const tokenFingerprint = t => crypto.createHash('sha256').update(String(t)).digest('hex').slice(0, 12);

// Scrub any secret-looking material from error text before it is persisted or
// printed (defense in depth — messages we build carry no secrets by design).
const scrubSecrets = s => String(s || '')
  .replace(/(Zoho-)?oauthtoken\s+\S+/gi, 'oauthtoken [REDACTED]')
  .replace(/(refresh_token|access_token|client_secret|code)=[^&\s"']+/gi, '$1=[REDACTED]');

// Preserve the ORIGINAL exception, sanitized: name/message/code/errno/syscall/
// hostname/type + the full cause chain + a trimmed stack. Nothing is collapsed.
function serializeError(err, depth = 0) {
  if (!err || depth > 4) return null;
  return {
    name: err.name || null,
    type: err.constructor ? err.constructor.name : null,
    message: scrubSecrets(err.message).slice(0, 400) || null,
    code: err.code != null ? String(err.code) : null,
    errno: err.errno != null ? err.errno : null,
    syscall: err.syscall || null,
    hostname: err.hostname || null,
    classification: err.classification || null,
    stack: depth === 0 ? scrubSecrets(String(err.stack || '')).split('\n').slice(0, 8).join('\n') : undefined,
    cause: err.cause ? serializeError(err.cause, depth + 1) : null,
  };
}

// HTTP-layer classification once a REAL response exists (status never 0 here).
function classifyHttp(status, body) {
  if (status >= 200 && status < 300) return null;
  const desc = String((body && body.status && body.status.description) || (body && body.errorCode) || '').toUpperCase();
  const raw = typeof body === 'string' ? body.toUpperCase() : JSON.stringify(body || '').toUpperCase();
  if (status === 401) return raw.includes('INVALID_OAUTHSCOPE') || desc.includes('SCOPE') ? 'oauth_scope_denied' : 'http_401';
  if (status === 403) return 'http_403';
  if (status === 429) return 'http_429';
  if (status === 404 && /ACCOUNT ID .* (IS )?INVALID/.test(raw)) return 'zoho_account_mismatch';
  return 'zoho_api_error';
}

// Full transport diagnostics for a failed fetch. Node's undici throws a generic
// "TypeError: fetch failed" whose REAL cause hangs off err.cause (possibly
// several links deep), carrying code/errno/syscall/hostname/address/port. A hard
// per-request timeout throws a TimeoutError/AbortError instead. We walk the whole
// cause chain, classify the failure (dns | tls | connection_refused |
// connection_reset | timeout | unreachable | …), and keep every field + stack, so
// an "HTTP 0" is never opaque again.
function transportDetail(err, url) {
  const chain = [];
  let e = err, depth = 0;
  while (e && depth < 6) {
    chain.push({
      name: e.name, message: String(e.message || '').slice(0, 300),
      code: e.code, errno: e.errno, syscall: e.syscall,
      hostname: e.hostname, address: e.address, port: e.port,
    });
    e = e.cause; depth++;
  }
  const root = chain[chain.length - 1] || {};
  const codeStr = [err.code, root.code, err.name, root.name, err.message, root.message].join(' ');
  let kind = 'unknown';
  if (err.name === 'TimeoutError' || err.name === 'AbortError' || /timeout|aborted/i.test(codeStr)) kind = 'timeout';
  else if (root.code === 'ENOTFOUND' || root.syscall === 'getaddrinfo' || /EAI_AGAIN/.test(codeStr)) kind = 'dns';
  else if (root.code === 'ECONNREFUSED') kind = 'connection_refused';
  else if (root.code === 'ECONNRESET' || /ECONNRESET/.test(codeStr)) kind = 'connection_reset';
  else if (root.code === 'EHOSTUNREACH' || root.code === 'ENETUNREACH') kind = 'unreachable';
  else if (root.code === 'ETIMEDOUT') kind = 'timeout';
  else if (root.code === 'EPROTO' || /CERT|TLS|SSL|self[- ]signed|altnames|DEPTH_ZERO|UNABLE_TO_VERIFY|HANDSHAKE/i.test(codeStr)) kind = 'tls';
  let host = null; try { host = new URL(url).host; } catch { /* keep null */ }
  return {
    kind, host,
    code: err.code || root.code || null,
    errno: err.errno != null ? err.errno : (root.errno != null ? root.errno : null),
    syscall: err.syscall || root.syscall || null,
    hostname: err.hostname || root.hostname || host || null,
    address: root.address || null, port: root.port || null,
    causeChain: chain,
    stack: String(err.stack || '').slice(0, 4000),
  };
}

const READ_SCOPES = [
  'ZohoMail.accounts.READ',
  'ZohoMail.folders.READ',
  'ZohoMail.messages.READ',
  'ZohoMail.organization.accounts.READ',
  'ZohoMail.organization.groups.READ',
].join(',');

const REQUEST_TIMEOUT_MS = Number(process.env.MADAR_REQUEST_TIMEOUT_MS || 20000);
const MIN_INTERVAL_MS = Math.ceil(60000 / Number(process.env.MADAR_MAX_RPM || 25));

class ZohoClient {
  constructor(connection) {
    this.conn = connection;
    this.accessToken = null;
    this.expiry = 0;
    this._lastCall = 0;
  }

  // Client-level rate budget: EVERY call (discovery probes included) is
  // spaced to stay under Zoho's documented ~30 req/min, with a hard
  // per-request timeout. No endpoint is ever hammered or retried blindly.
  async _pace() {
    const wait = this._lastCall + MIN_INTERVAL_MS - Date.now();
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    this._lastCall = Date.now();
  }

  static async forConnection(connectionId) {
    const conn = await one('SELECT * FROM connections WHERE id = $1', [connectionId]);
    if (!conn) throw new Error('Connection not found: ' + connectionId);
    return new ZohoClient(conn);
  }

  // Connection-scoped SHARED client. A fresh client per sync cycle loses the
  // in-memory access token, forcing a Zoho token refresh per mailbox per cycle —
  // Zoho rate-limits refresh-token usage, so that design produced intermittent
  // auth failures. One cached instance per connection reuses the token across
  // cycles AND serializes request pacing across all mailboxes of the connection
  // (Zoho's rate limit is per-org, not per-mailbox). The connection row is
  // re-read on every call so config changes (bases, secret) apply immediately.
  static async cachedForConnection(connectionId) {
    const id = Number(connectionId);
    const conn = await one('SELECT * FROM connections WHERE id = $1', [id]);
    if (!conn) { ZohoClient._cache.delete(id); throw new Error('Connection not found: ' + connectionId); }
    let client = ZohoClient._cache.get(id);
    if (!client) { client = new ZohoClient(conn); ZohoClient._cache.set(id, client); }
    else client.conn = conn; // refresh config; token cache (memory+DB) stays valid
    return client;
  }

  authorizeUrl(redirectUri) {
    const u = new URL('/oauth/v2/auth', this.conn.accounts_base);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', this.conn.client_id);
    u.searchParams.set('scope', this.conn.scopes || READ_SCOPES);
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('access_type', 'offline');
    u.searchParams.set('prompt', 'consent');
    return u.toString();
  }

  async exchangeCode(code, redirectUri) {
    const res = await fetch(new URL('/oauth/v2/token', this.conn.accounts_base), {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code', code,
        client_id: this.conn.client_id,
        client_secret: decrypt(this.conn.client_secret_enc),
        redirect_uri: redirectUri,
      }),
    });
    const json = await res.json();
    if (!res.ok || json.error || !json.refresh_token) {
      throw new Error('Zoho token exchange failed: ' + (json.error || res.status));
    }
    this.accessToken = json.access_token;
    this.expiry = Date.now() + (json.expires_in - 60) * 1000;
    await q(`UPDATE connections SET refresh_token_enc = $1, access_token_enc = $2,
             access_token_expires_at = $3, status = 'connected', status_detail = '' WHERE id = $4`,
      [encrypt(json.refresh_token), encrypt(this.accessToken), new Date(this.expiry), this.conn.id]);
  }

  // Token acquisition with FULL lifecycle evidence (this.lastTokenEvidence —
  // sanitized: fingerprint prefix, source, expiry, refresh decision; never the
  // token). Failures throw typed ZohoAuthError with a precise classification —
  // they are OAuth failures, not "HTTP 0".
  async token() {
    const ev = { source: null, fingerprint: null, issuedAt: null,
      expiresAt: null, nowAt: Date.now(), remainingSec: null, refresh: null };
    const finish = (token) => {
      ev.fingerprint = tokenFingerprint(token);
      ev.expiresAt = this.expiry;
      ev.remainingSec = Math.round((this.expiry - Date.now()) / 1000);
      this.lastTokenEvidence = ev;
      return token;
    };
    if (this.accessToken && Date.now() < this.expiry) { ev.source = 'memory'; return finish(this.accessToken); }
    if (!this.conn.refresh_token_enc) {
      this.lastTokenEvidence = { ...ev, source: 'none' };
      throw new ZohoAuthError('oauth_token_missing', 'Connection not authorized yet (no refresh token).');
    }
    // Refresh-token concurrency guard: a PostgreSQL advisory lock per
    // connection serializes refreshes across every process/worker, so
    // parallel syncs can never race Zoho's token endpoint.
    const { tx } = require('../../core/db');
    return tx(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [0x4d41, Number(this.conn.id)]);
      if (this.accessToken && Date.now() < this.expiry) { ev.source = 'memory'; return finish(this.accessToken); } // refreshed while waiting
      const fresh = (await client.query(
        `SELECT refresh_token_enc, access_token_enc, access_token_expires_at
         FROM connections WHERE id = $1`, [this.conn.id])).rows[0];
      // Persisted token cache (encrypted at rest): another process — or this one
      // before a restart — may already hold a valid access token. Reusing it is
      // what keeps refreshes at ~1/hour/connection instead of one per mailbox per
      // cycle (Zoho rate-limits refresh-token usage; churn = intermittent 4xx).
      const expMs = fresh.access_token_expires_at ? new Date(fresh.access_token_expires_at).getTime() : 0;
      if (fresh.access_token_enc && expMs > Date.now()) {
        try {
          this.accessToken = decrypt(fresh.access_token_enc);
          this.expiry = expMs;
          ev.source = 'postgres_cache';
          return finish(this.accessToken);
        } catch (e) {
          // undecryptable cached ACCESS token → safe to fall through to refresh,
          // but record the decision so the evidence shows why a refresh happened
          ev.refresh = { decision: 'refresh', reason: 'cached access token undecryptable (key rotation?)' };
        }
      } else {
        ev.refresh = { decision: 'refresh',
          reason: fresh.access_token_enc ? `cached token expired ${Math.round((Date.now() - expMs) / 1000)}s ago` : 'no cached access token' };
      }
      // the REFRESH token itself failing to decrypt is fatal and must say so —
      // this was previously an anonymous throw that surfaced as "HTTP 0"
      let refreshToken;
      try { refreshToken = decrypt(fresh.refresh_token_enc); }
      catch (e) {
        this.lastTokenEvidence = ev;
        throw new ZohoAuthError('oauth_token_decrypt_failed',
          'Stored refresh token cannot be decrypted — MADAR_ENCRYPTION_KEY differs from the one that stored it (key rotation without re-encryption, or a recreated container with a new .env). Re-authorize the connection or restore the original key.',
          { cause: e });
      }
      let clientSecret;
      try { clientSecret = decrypt(this.conn.client_secret_enc); }
      catch (e) {
        this.lastTokenEvidence = ev;
        throw new ZohoAuthError('oauth_token_decrypt_failed',
          'Stored client secret cannot be decrypted — encryption key mismatch (see refresh-token note).', { cause: e });
      }
      ev.refresh = { ...(ev.refresh || { decision: 'refresh', reason: 'memory+cache miss' }), startedAt: Date.now() };
      const res = await fetch(new URL('/oauth/v2/token', this.conn.accounts_base), {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: this.conn.client_id,
          client_secret: clientSecret,
        }),
      });
      const json = await res.json().catch(() => ({}));
      ev.refresh.finishedAt = Date.now();
      ev.refresh.httpStatus = res.status;
      if (!res.ok || json.error || !json.access_token) {
        ev.refresh.outcome = 'failed';
        ev.refresh.zohoError = scrubSecrets(json.error || json.error_description || String(res.status)).slice(0, 200);
        this.lastTokenEvidence = ev;
        throw new ZohoAuthError('oauth_refresh_failed',
          `Zoho token refresh failed: ${ev.refresh.zohoError}` +
          (String(json.error || '').includes('invalid_grant')
            ? ' — the refresh token was revoked or superseded (Zoho caps live refresh tokens per client); re-authorize the connection from the admin panel.' : ''),
          { zohoError: json.error || null, httpStatus: res.status });
      }
      ev.refresh.outcome = 'ok';
      this.accessToken = json.access_token; // plaintext in memory only — encrypted before persisting, never logged
      this.expiry = Date.now() + (json.expires_in - 60) * 1000;
      ev.source = 'refresh';
      ev.issuedAt = Date.now();
      ZohoClient._refreshes++;
      await client.query('UPDATE connections SET access_token_enc = $1, access_token_expires_at = $2 WHERE id = $3',
        [encrypt(this.accessToken), new Date(this.expiry), this.conn.id]);
      return finish(this.accessToken);
    });
  }

  // Raw GET: never throws; every result carries phase-separated evidence.
  // PHASES ARE CAUGHT SEPARATELY — an OAuth failure is classified oauth_*, a
  // socket failure unknown_transport_error/<kind>, a timeout request_timeout, a
  // body-read failure malformed_response. Nothing is ever collapsed into a bare
  // "HTTP 0": the original exception is preserved (sanitized) in body.originalError
  // and the request evidence in meta (redacted headers, timing, timeout, abort).
  async get(pathname, { raw = false } = {}) {
    const url = new URL(pathname, this.conn.api_base).toString();
    const meta = {
      url, method: 'GET', host: new URL(url).host,
      headers: { Authorization: '[REDACTED Zoho-oauthtoken]' },
      timeoutMs: REQUEST_TIMEOUT_MS, abortControllerCreated: true, abortFired: false, abortReason: null,
      attempt: 1, retriesConfigured: 0,
      startedAt: Date.now(), finishedAt: null, elapsedMs: null, phase: 'oauth',
    };
    const done = (r) => { meta.finishedAt = Date.now(); meta.elapsedMs = meta.finishedAt - meta.startedAt; return { ...r, meta }; };

    await this._pace();
    let token;
    try {
      token = await this.token();
    } catch (err) {
      // OAuth phase — no request was ever sent. Classify precisely.
      return done({ url, status: 0, phase: 'oauth',
        classification: err.classification || 'application_exception',
        oauth: this.lastTokenEvidence || null,
        body: { error: scrubSecrets(err.message), originalError: serializeError(err) } });
    }
    meta.phase = 'fetch';
    meta.oauth = this.lastTokenEvidence ? {
      source: this.lastTokenEvidence.source, fingerprint: this.lastTokenEvidence.fingerprint,
      expiresAt: this.lastTokenEvidence.expiresAt, remainingSec: this.lastTokenEvidence.remainingSec,
    } : null;
    let res;
    try {
      res = await fetch(url, {
        headers: { Authorization: 'Zoho-oauthtoken ' + token },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      const timedOut = err.name === 'TimeoutError' || (err.name === 'AbortError' && Date.now() - meta.startedAt >= REQUEST_TIMEOUT_MS - 50);
      meta.abortFired = err.name === 'TimeoutError' || err.name === 'AbortError';
      meta.abortReason = meta.abortFired ? (timedOut ? `AbortSignal.timeout(${REQUEST_TIMEOUT_MS}ms) fired` : 'aborted before timeout') : null;
      const transport = transportDetail(err, url);
      return done({ url, status: 0, phase: 'fetch',
        classification: timedOut ? 'request_timeout'
          : err.name === 'AbortError' ? 'request_aborted'
          : 'unknown_transport_error',
        body: { transportError: scrubSecrets(err.message), transport, originalError: serializeError(err) } });
    }
    meta.phase = 'read';
    try {
      if (raw && res.ok) return done({ url, status: res.status, body: Buffer.from(await res.arrayBuffer()) });
      const text = await res.text();
      let body; try { body = JSON.parse(text); } catch { body = text.slice(0, 2000); }
      return done({ url, status: res.status, body, classification: classifyHttp(res.status, body),
        responseHeaders: { 'content-type': res.headers.get('content-type') || null,
          'x-request-id': res.headers.get('x-request-id') || res.headers.get('x-zoho-requestid') || null } });
    } catch (err) {
      return done({ url, status: res.status, phase: 'read', classification: 'malformed_response',
        body: { error: scrubSecrets(err.message), originalError: serializeError(err) } });
    }
  }

  // ---- Official endpoints under test (see ARCHITECTURE.md access matrix) ----
  getAccounts()                 { return this.get('/api/accounts'); }
  getOrganization()             { return this.get('/api/organization'); }
  getOrgAccounts(zoid)          { return this.get(`/api/organization/${zoid}/accounts?start=0&limit=500`); }
  getGroups(zoid, start = 0, limit = 100) { return this.get(`/api/organization/${zoid}/groups?start=${start}&limit=${limit}`); }
  getGroupDetails(zoid, gid)    { return this.get(`/api/organization/${zoid}/groups/${gid}`); }
  getGroupModeration(zoid, gid) { return this.get(`/api/organization/${zoid}/groups/${gid}/messages?start=0&limit=25`); }
  getFolders(accountId)         { return this.get(`/api/accounts/${accountId}/folders`); }
  listMessages(accountId, folderId, { limit = 100, start = 1 } = {}) {
    return this.get(`/api/accounts/${accountId}/messages/view?folderId=${folderId}&limit=${limit}&start=${start}`);
  }
  // Dedicated archived view (proven on the real tenant: HTTP 200 with messages).
  listArchivedMessages(accountId, { limit = 100, start = 1 } = {}) {
    return this.get(`/api/accounts/${accountId}/messages/view?status=archived&limit=${limit}&start=${start}`);
  }
  getMessageContent(accountId, folderId, messageId) {
    return this.get(`/api/accounts/${accountId}/folders/${folderId}/messages/${messageId}/content`);
  }
  getAttachmentInfo(accountId, folderId, messageId) {
    return this.get(`/api/accounts/${accountId}/folders/${folderId}/messages/${messageId}/attachmentinfo`);
  }
  downloadAttachment(accountId, folderId, messageId, attachmentId) {
    return this.get(`/api/accounts/${accountId}/folders/${folderId}/messages/${messageId}/attachments/${attachmentId}`, { raw: true });
  }
}

ZohoClient._cache = new Map();  // connection id -> shared client instance
ZohoClient._refreshes = 0;      // process-lifetime refresh count (observability)

module.exports = { ZohoClient, ZohoAuthError, READ_SCOPES, classifyHttp, serializeError, tokenFingerprint };
