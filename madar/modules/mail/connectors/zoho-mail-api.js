// Live read connector for any Zoho mailbox whose detection probe PROVED a
// working message-read id (accountId or org-level id). Used for user
// mailboxes and for shared mailboxes if/when Zoho exposes live read for them.
const lc = s => String(s || '').toLowerCase();

// Typed API error: carries endpoint + HTTP status + a sanitized response
// sample (status/field-names only — never bodies/PII) so diagnostics can show
// the real cause instead of a flattened string.
class ZohoApiError extends Error {
  constructor(stage, endpoint, status, body) {
    super(`Zoho ${stage} failed: HTTP ${status} at ${endpoint}`);
    this.name = 'ZohoApiError';
    this.stage = stage;
    this.endpoint = endpoint;
    this.httpStatus = status;
    const data = body && body.data;
    this.responseSample = {
      status,
      description: (body && body.status && body.status.description) || undefined,
      moreInfo: (data && data.moreInfo) || undefined,
      errorCode: (body && body.status && body.status.code) || (body && body.errorCode) || undefined,
      fields: Array.isArray(data) && data[0] ? Object.keys(data[0]).sort() : undefined,
    };
  }
}

class ZohoMailApiConnector {
  constructor(zoho, mailbox) {
    this.zoho = zoho;
    this.mailbox = mailbox;
    this.caps = typeof mailbox.capabilities === 'string'
      ? JSON.parse(mailbox.capabilities || '{}')
      : (mailbox.capabilities || {}); // JSONB arrives as an object from pg
    if (!this.caps.workingId) throw new Error('mail_api strategy requires a probe-proven working id');
    this.id = this.caps.workingId;
  }

  capabilities() { return this.caps; }

  async listFolders() {
    this.lastEndpoint = `/api/accounts/${this.id}/folders`;
    const r = await this.zoho.getFolders(this.id);
    if (r.status !== 200) throw new ZohoApiError('list_folders', r.url || this.lastEndpoint, r.status, r.body);
    return ((r.body && r.body.data) || []).map(f => ({
      providerFolderId: String(f.folderId),
      name: f.folderName,
      type: lc(f.folderType || ''),
    }));
  }

  async listMessages(folder, { start = 1, limit = 100 } = {}) {
    this.lastEndpoint = `/api/accounts/${this.id}/messages/view?folderId=${folder.providerFolderId}`;
    const r = await this.zoho.listMessages(this.id, folder.providerFolderId, { start, limit });
    if (r.status !== 200) throw new ZohoApiError('fetch_messages', r.url || this.lastEndpoint, r.status, r.body);
    return ((r.body && r.body.data) || []).map(m => ({
      providerMessageId: String(m.messageId),
      // Real tenants' messages/view carries NO RFC header field — dedup uses the
      // v2 fingerprint. Kept optional so a future header source can fill it.
      rfcMessageId: m.messageIdHeader || m.messageId_header || m.rfcMessageId || '',
      threadId: String(m.threadId || ''),
      from: m.fromAddress || m.sender || '',
      fromName: m.senderName || '',
      to: m.toAddress || '',
      cc: m.ccAddress || '',
      subject: m.subject || '',
      snippet: m.summary || '',
      receivedAt: Number(m.receivedTime) || Date.now(),
      hasAttachments: m.hasAttachment === '1' || m.hasAttachment === 1 || m.hasAttachment === true,
      direction: folder.type === 'sent' ? 'out' : 'in',
    }));
  }

  async getBody(folder, providerMessageId) {
    const r = await this.zoho.getMessageContent(this.id, folder.providerFolderId, providerMessageId);
    if (r.status !== 200) return null;
    const d = (r.body && r.body.data) || {};
    return d.content || null;
  }

  async listAttachments(folder, providerMessageId) {
    const r = await this.zoho.getAttachmentInfo(this.id, folder.providerFolderId, providerMessageId);
    if (r.status !== 200) return [];
    return (((r.body && r.body.data) || {}).attachments || []).map(a => ({
      providerAttachmentId: String(a.attachmentId),
      name: a.attachmentName,
      size: Number(a.attachmentSize || 0),
      mime: a.attachmentType || '',
    }));
  }

  async downloadAttachment(folder, providerMessageId, providerAttachmentId) {
    const r = await this.zoho.downloadAttachment(this.id, folder.providerFolderId, providerMessageId, providerAttachmentId);
    if (r.status !== 200 || !Buffer.isBuffer(r.body)) throw new Error(`attachment download failed (${r.status})`);
    return r.body;
  }
}

module.exports = { ZohoMailApiConnector, ZohoApiError };
