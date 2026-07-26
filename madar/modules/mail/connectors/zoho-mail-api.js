// Live read connector for any Zoho mailbox whose detection probe PROVED a
// working message-read id (accountId or org-level id). Used for user
// mailboxes and for shared mailboxes if/when Zoho exposes live read for them.
const lc = s => String(s || '').toLowerCase();

// Typed API error: carries endpoint + HTTP status + a sanitized response
// sample (status/field-names only — never bodies/PII) so diagnostics can show
// the real cause instead of a flattened string.
class ZohoApiError extends Error {
  // r = the full get() result: { url, status, body, classification, phase, meta, oauth, responseHeaders }
  constructor(stage, endpoint, status, body, r = null) {
    const t = body && body.transport;
    const cls = (r && r.classification) || (body && body.classification) || null;
    const phase = (r && r.phase) || null;
    // The headline names the REAL failure class — never a bare "HTTP 0":
    //   oauth phase  → "Zoho list_folders OAuth failure (oauth_refresh_failed): …"
    //   fetch phase  → "Zoho list_folders transport failure (dns ENOTFOUND) at …"
    //   HTTP status  → "Zoho list_folders failed: HTTP 401 (oauth_scope_denied) at …"
    let headline;
    if (status === 0 && phase === 'oauth') {
      headline = `Zoho ${stage} OAuth failure (${cls}): ${(body && body.error) || 'token acquisition failed'}`;
    } else if (status === 0) {
      headline = `Zoho ${stage} ${cls === 'request_timeout' ? 'timeout' : 'transport failure'} (${t ? t.kind : cls || 'unknown'}${t && t.code ? ' ' + t.code : ''}) at ${endpoint}`;
    } else {
      headline = `Zoho ${stage} failed: HTTP ${status}${cls ? ' (' + cls + ')' : ''} at ${endpoint}`;
    }
    super(headline);
    this.name = 'ZohoApiError';
    this.stage = stage;
    this.endpoint = endpoint;
    this.httpStatus = status;
    this.classification = cls || (status === 0 ? 'unknown_transport_error' : 'zoho_api_error');
    this.phase = phase;
    this.transport = t || null;             // full transport diagnosis (fetch phase)
    this.oauth = (r && r.oauth) || null;    // sanitized token evidence (fingerprint/source/expiry only)
    this.requestMeta = (r && r.meta) || null; // redacted headers, timing, timeout, abort
    this.originalError = (body && body.originalError) || null; // preserved, sanitized
    // Keep the deepest real stack when one exists — it points at the actual
    // failure, not this constructor.
    if (t && t.stack) this.stack = `${this.name}: ${headline}\n${t.stack}`;
    else if (this.originalError && this.originalError.stack) this.stack = `${this.name}: ${headline}\n${this.originalError.stack}`;
    const data = body && body.data;
    this.responseSample = {
      status,
      classification: this.classification,
      phase,
      transport: t ? {
        kind: t.kind, code: t.code, errno: t.errno, syscall: t.syscall,
        hostname: t.hostname, address: t.address, port: t.port, host: t.host,
        causeChain: t.causeChain,
      } : undefined,
      oauth: this.oauth || undefined,
      originalError: this.originalError || undefined,
      requestMeta: this.requestMeta ? { timeoutMs: this.requestMeta.timeoutMs, elapsedMs: this.requestMeta.elapsedMs,
        abortFired: this.requestMeta.abortFired, abortReason: this.requestMeta.abortReason,
        host: this.requestMeta.host, startedAt: this.requestMeta.startedAt } : undefined,
      responseHeaders: (r && r.responseHeaders) || undefined,
      description: (body && body.status && body.status.description) || (status === 0 && body && (body.error || body.transportError)) || undefined,
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
    if (r.status !== 200) throw new ZohoApiError('list_folders', r.url || this.lastEndpoint, r.status, r.body, r);
    const folders = ((r.body && r.body.data) || []).map(f => ({
      providerFolderId: String(f.folderId),
      name: f.folderName,
      type: lc(f.folderType || ''),
    }));
    // Virtual Archived folder — Zoho exposes archived mail through the dedicated
    // view messages/view?status=archived (proven on the real tenant), NOT only
    // through listed folders. Mapping it as a folder runs it through the exact
    // standard pipeline: cold rotation, pagination, terminal-page detection,
    // persisted cursor, fp3 dedup (so mail also present in a listed Archive
    // folder is never duplicated). Skipped only when this tenant has proven the
    // parameter unsupported (capability recorded by the sync engine).
    if (!String(this.caps.archivedView || '').startsWith('unsupported')) {
      folders.push({ providerFolderId: ZohoMailApiConnector.VIRTUAL_ARCHIVED_ID,
        name: 'Archived (Zoho)', type: 'archive', virtual: true });
    }
    return folders;
  }

  async listMessages(folder, { start = 1, limit = 100 } = {}) {
    const isVirtualArchived = folder.providerFolderId === ZohoMailApiConnector.VIRTUAL_ARCHIVED_ID;
    this.lastEndpoint = isVirtualArchived
      ? `/api/accounts/${this.id}/messages/view?status=archived`
      : `/api/accounts/${this.id}/messages/view?folderId=${folder.providerFolderId}`;
    const r = isVirtualArchived
      ? await this.zoho.listArchivedMessages(this.id, { start, limit })
      : await this.zoho.listMessages(this.id, folder.providerFolderId, { start, limit });
    if (r.status !== 200) throw new ZohoApiError(isVirtualArchived ? 'fetch_archived' : 'fetch_messages',
      r.url || this.lastEndpoint, r.status, r.body, r);
    return ((r.body && r.body.data) || []).map(m => ({
      // the message's OWN folder id — archived-view rows live in their original
      // folder, which is what body/attachment endpoints need
      sourceFolderId: String(m.folderId || ''),
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
      // SENT time drives the canonical fingerprint (copy-stable across mailboxes
      // and identical to the eDiscovery EML Date: header). receivedTime is
      // per-mailbox and used only for display/ordering.
      sentAt: Number(m.sentDateInGMT) || Number(m.receivedTime) || Date.now(),
      hasAttachments: m.hasAttachment === '1' || m.hasAttachment === 1 || m.hasAttachment === true,
      direction: folder.type === 'sent' ? 'out' : 'in',
    }));
  }

  // For the virtual archived folder, per-message endpoints need the message's
  // ORIGINAL folder id (carried on the row as sourceFolderId).
  _effectiveFolderId(folder, msg) {
    if (folder.providerFolderId === ZohoMailApiConnector.VIRTUAL_ARCHIVED_ID) {
      return (msg && msg.sourceFolderId) || null;
    }
    return folder.providerFolderId;
  }

  // raw headers, or null when unavailable; the HTTP status rides along so the
  // caller can distinguish "no headers" from "endpoint unsupported here"
  async getHeaders(folder, providerMessageId, msg = null) {
    const fid = this._effectiveFolderId(folder, msg);
    if (!fid) return { status: 0, headers: null };
    const r = await this.zoho.getMessageHeaders(this.id, fid, providerMessageId);
    const d = (r.body && r.body.data) || {};
    return { status: r.status, headers: r.status === 200 ? (d.headerContent || d.header || null) : null };
  }

  async getBody(folder, providerMessageId, msg = null) {
    const fid = this._effectiveFolderId(folder, msg);
    if (!fid) return null;
    const r = await this.zoho.getMessageContent(this.id, fid, providerMessageId);
    if (r.status !== 200) return null;
    const d = (r.body && r.body.data) || {};
    return d.content || null;
  }

  async listAttachments(folder, providerMessageId, msg = null) {
    const fid = this._effectiveFolderId(folder, msg);
    if (!fid) return [];
    const r = await this.zoho.getAttachmentInfo(this.id, fid, providerMessageId);
    if (r.status !== 200) return [];
    return (((r.body && r.body.data) || {}).attachments || []).map(a => ({
      providerAttachmentId: String(a.attachmentId),
      name: a.attachmentName,
      size: Number(a.attachmentSize || 0),
      mime: a.attachmentType || '',
    }));
  }

  async downloadAttachment(folder, providerMessageId, providerAttachmentId, msg = null) {
    const fid = this._effectiveFolderId(folder, msg) || folder.providerFolderId;
    const r = await this.zoho.downloadAttachment(this.id, fid, providerMessageId, providerAttachmentId);
    if (r.status !== 200 || !Buffer.isBuffer(r.body)) throw new Error(`attachment download failed (${r.status})`);
    return r.body;
  }
}

ZohoMailApiConnector.VIRTUAL_ARCHIVED_ID = 'zoho:archived';

module.exports = { ZohoMailApiConnector, ZohoApiError };
