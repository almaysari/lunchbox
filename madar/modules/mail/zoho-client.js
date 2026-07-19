// Low-level Zoho Mail API client bound to an organization connection.
// Every call returns { url, status, body } WITHOUT throwing on HTTP errors —
// the detection engine needs literal API responses as evidence.
// Docs: https://www.zoho.com/mail/help/api/
const { one, q } = require('../../core/db');
const { decrypt, encrypt } = require('../../core/crypto');

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

  async token() {
    if (this.accessToken && Date.now() < this.expiry) return this.accessToken;
    if (!this.conn.refresh_token_enc) throw new Error('Connection not authorized yet (no refresh token).');
    // Refresh-token concurrency guard: a PostgreSQL advisory lock per
    // connection serializes refreshes across every process/worker, so
    // parallel syncs can never race Zoho's token endpoint.
    const { tx } = require('../../core/db');
    return tx(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [0x4d41, Number(this.conn.id)]);
      if (this.accessToken && Date.now() < this.expiry) return this.accessToken; // refreshed while waiting
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
          return this.accessToken;
        } catch { /* undecryptable (key rotation) → fall through to refresh */ }
      }
      const res = await fetch(new URL('/oauth/v2/token', this.conn.accounts_base), {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: decrypt(fresh.refresh_token_enc),
          client_id: this.conn.client_id,
          client_secret: decrypt(this.conn.client_secret_enc),
        }),
      });
      const json = await res.json();
      if (!res.ok || json.error) throw new Error('Zoho token refresh failed: ' + (json.error || res.status));
      this.accessToken = json.access_token; // plaintext in memory only — encrypted before persisting, never logged
      this.expiry = Date.now() + (json.expires_in - 60) * 1000;
      ZohoClient._refreshes++;
      await client.query('UPDATE connections SET access_token_enc = $1, access_token_expires_at = $2 WHERE id = $3',
        [encrypt(this.accessToken), new Date(this.expiry), this.conn.id]);
      return this.accessToken;
    });
  }

  // Raw GET: never throws on HTTP errors; body is parsed JSON or raw text.
  async get(pathname, { raw = false } = {}) {
    const url = new URL(pathname, this.conn.api_base).toString();
    try {
      await this._pace();
      const token = await this.token();
      const res = await fetch(url, {
        headers: { Authorization: 'Zoho-oauthtoken ' + token },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (raw && res.ok) return { url, status: res.status, body: Buffer.from(await res.arrayBuffer()) };
      const text = await res.text();
      let body; try { body = JSON.parse(text); } catch { body = text.slice(0, 2000); }
      return { url, status: res.status, body };
    } catch (err) {
      // status 0 = never reached HTTP; body carries the FULL transport diagnosis
      // (kind + code/errno/syscall/hostname/address/port + cause chain + stack).
      return { url, status: 0, body: { transportError: String(err.message || err), transport: transportDetail(err, url) } };
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

module.exports = { ZohoClient, READ_SCOPES };
