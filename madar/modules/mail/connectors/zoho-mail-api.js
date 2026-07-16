// Live read connector for any Zoho mailbox whose detection probe PROVED a
// working message-read id (accountId or org-level id). Used for user
// mailboxes and for shared mailboxes if/when Zoho exposes live read for them.
const lc = s => String(s || '').toLowerCase();

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
    const r = await this.zoho.getFolders(this.id);
    if (r.status !== 200) throw new Error(`folders failed (${r.status}): ${JSON.stringify(r.body).slice(0, 200)}`);
    return ((r.body && r.body.data) || []).map(f => ({
      providerFolderId: String(f.folderId),
      name: f.folderName,
      type: lc(f.folderType || ''),
    }));
  }

  async listMessages(folder, { start = 1, limit = 100 } = {}) {
    const r = await this.zoho.listMessages(this.id, folder.providerFolderId, { start, limit });
    if (r.status !== 200) throw new Error(`messages failed (${r.status}): ${JSON.stringify(r.body).slice(0, 200)}`);
    return ((r.body && r.body.data) || []).map(m => ({
      providerMessageId: String(m.messageId),
      rfcMessageId: m.messageIdHeader || '',
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

module.exports = { ZohoMailApiConnector };
