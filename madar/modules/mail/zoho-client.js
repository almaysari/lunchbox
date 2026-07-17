// Low-level Zoho Mail API client bound to an organization connection.
// Every call returns { url, status, body } WITHOUT throwing on HTTP errors —
// the detection engine needs literal API responses as evidence.
// Docs: https://www.zoho.com/mail/help/api/
const { one, q } = require('../../core/db');
const { decrypt, encrypt } = require('../../core/crypto');

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
    await q("UPDATE connections SET refresh_token_enc = $1, status = 'connected', status_detail = '' WHERE id = $2",
      [encrypt(json.refresh_token), this.conn.id]);
    this.accessToken = json.access_token;
    this.expiry = Date.now() + (json.expires_in - 60) * 1000;
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
      const fresh = await client.query('SELECT refresh_token_enc FROM connections WHERE id = $1', [this.conn.id]);
      const res = await fetch(new URL('/oauth/v2/token', this.conn.accounts_base), {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: decrypt(fresh.rows[0].refresh_token_enc),
          client_id: this.conn.client_id,
          client_secret: decrypt(this.conn.client_secret_enc),
        }),
      });
      const json = await res.json();
      if (!res.ok || json.error) throw new Error('Zoho token refresh failed: ' + (json.error || res.status));
      this.accessToken = json.access_token; // memory only — never persisted or logged
      this.expiry = Date.now() + (json.expires_in - 60) * 1000;
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
      return { url, status: 0, body: { transportError: String(err.message || err) } };
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

module.exports = { ZohoClient, READ_SCOPES };
