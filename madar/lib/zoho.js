// Zoho Mail API client (OAuth 2.0, data-center aware).
// Docs: https://www.zoho.com/mail/help/api/
const { loadTokens, saveTokens } = require('./store');

const SCOPES = 'ZohoMail.accounts.READ,ZohoMail.folders.READ,ZohoMail.messages.READ';

class ZohoClient {
  constructor(cfg) {
    this.cfg = cfg;
    this.accessToken = null;
    this.accessTokenExpiry = 0;
  }

  authorizeUrl() {
    const u = new URL('/oauth/v2/auth', this.cfg.ZOHO_ACCOUNTS_BASE);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', this.cfg.ZOHO_CLIENT_ID);
    u.searchParams.set('scope', SCOPES);
    u.searchParams.set('redirect_uri', this.cfg.ZOHO_REDIRECT_URI);
    u.searchParams.set('access_type', 'offline');
    u.searchParams.set('prompt', 'consent');
    return u.toString();
  }

  async exchangeCode(code) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: this.cfg.ZOHO_CLIENT_ID,
      client_secret: this.cfg.ZOHO_CLIENT_SECRET,
      redirect_uri: this.cfg.ZOHO_REDIRECT_URI,
    });
    const res = await fetch(new URL('/oauth/v2/token', this.cfg.ZOHO_ACCOUNTS_BASE), {
      method: 'POST', body,
    });
    const json = await res.json();
    if (!res.ok || json.error) throw new Error('Zoho token exchange failed: ' + (json.error || res.status));
    saveTokens({ refresh_token: json.refresh_token, obtained_at: Date.now() });
    this.accessToken = json.access_token;
    this.accessTokenExpiry = Date.now() + (json.expires_in - 60) * 1000;
    return json;
  }

  hasConnection() {
    const t = loadTokens();
    return Boolean(t && t.refresh_token);
  }

  async getAccessToken() {
    if (this.accessToken && Date.now() < this.accessTokenExpiry) return this.accessToken;
    const tokens = loadTokens();
    if (!tokens || !tokens.refresh_token) throw new Error('Not connected: no refresh token. Visit /api/oauth/url first.');
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_id: this.cfg.ZOHO_CLIENT_ID,
      client_secret: this.cfg.ZOHO_CLIENT_SECRET,
    });
    const res = await fetch(new URL('/oauth/v2/token', this.cfg.ZOHO_ACCOUNTS_BASE), {
      method: 'POST', body,
    });
    const json = await res.json();
    if (!res.ok || json.error) throw new Error('Zoho token refresh failed: ' + (json.error || res.status));
    this.accessToken = json.access_token;
    this.accessTokenExpiry = Date.now() + (json.expires_in - 60) * 1000;
    return this.accessToken;
  }

  async api(pathname, { raw = false } = {}) {
    const token = await this.getAccessToken();
    const res = await fetch(new URL(pathname, this.cfg.ZOHO_MAIL_BASE), {
      headers: { Authorization: 'Zoho-oauthtoken ' + token },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Zoho API ${pathname} failed (${res.status}): ${text.slice(0, 300)}`);
    }
    if (raw) return Buffer.from(await res.arrayBuffer());
    const json = await res.json();
    return json.data;
  }

  // All mailboxes visible to the authorized user.
  getAccounts() {
    return this.api('/api/accounts');
  }

  getFolders(accountId) {
    return this.api(`/api/accounts/${accountId}/folders`);
  }

  listMessages(accountId, folderId, { limit = 100, start = 1 } = {}) {
    return this.api(`/api/accounts/${accountId}/messages/view?folderId=${folderId}&limit=${limit}&start=${start}`);
  }

  getAttachmentInfo(accountId, folderId, messageId) {
    return this.api(`/api/accounts/${accountId}/folders/${folderId}/messages/${messageId}/attachmentinfo`);
  }

  downloadAttachment(accountId, folderId, messageId, attachmentId) {
    return this.api(
      `/api/accounts/${accountId}/folders/${folderId}/messages/${messageId}/attachments/${attachmentId}`,
      { raw: true },
    );
  }
}

module.exports = { ZohoClient, SCOPES };
