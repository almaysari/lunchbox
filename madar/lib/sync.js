// Sync engine: pull messages from Zoho Mail, keep only CV attachments,
// dedupe by messageId, store attachments + candidate records locally.
const fs = require('fs');
const path = require('path');
const { loadDb, saveDb, CV_DIR } = require('./store');

const CV_EXTENSIONS = ['.pdf', '.doc', '.docx'];
const MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024;

function isCvFile(name) {
  return CV_EXTENSIONS.includes(path.extname(String(name)).toLowerCase());
}

function safeFileName(name) {
  return String(name).replace(/[^\w.؀-ۿ-]+/g, '_').slice(0, 120);
}

async function syncOnce(zoho, cfg) {
  const db = loadDb();
  const summary = { scanned: 0, imported: 0, skipped: 0, mailbox: null };

  const accounts = await zoho.getAccounts();
  if (!accounts || !accounts.length) throw new Error('No mailboxes visible to this OAuth user.');

  const wanted = (cfg.ZOHO_MAILBOX || '').toLowerCase();
  const account = wanted
    ? accounts.find(a =>
        String(a.mailboxAddress || a.primaryEmailAddress || '').toLowerCase() === wanted ||
        (a.emailAddress || []).some(e => String(e.mailId || '').toLowerCase() === wanted))
    : accounts[0];
  if (!account) {
    const seen = accounts.map(a => a.mailboxAddress || a.primaryEmailAddress).join(', ');
    throw new Error(`Mailbox "${cfg.ZOHO_MAILBOX}" not visible via API. Visible mailboxes: ${seen}. ` +
      'For a shared mailbox, forward its mail to a dedicated integration account and sync that instead.');
  }
  const accountId = account.accountId;
  summary.mailbox = account.mailboxAddress || account.primaryEmailAddress;

  const folders = await zoho.getFolders(accountId);
  const wantedFolder = cfg.ZOHO_FOLDER
    ? folders.find(f => String(f.folderName).toLowerCase() === cfg.ZOHO_FOLDER.toLowerCase())
    : folders.find(f => String(f.folderType || '').toLowerCase() === 'inbox' || String(f.folderName).toLowerCase() === 'inbox');
  if (!wantedFolder) throw new Error('Folder not found: ' + (cfg.ZOHO_FOLDER || 'Inbox'));
  const folderId = wantedFolder.folderId;

  let start = 1;
  const pageSize = 100;
  for (let page = 0; page < 20; page++) { // hard cap: 2000 messages per sync run
    const messages = await zoho.listMessages(accountId, folderId, { limit: pageSize, start });
    if (!messages || !messages.length) break;

    for (const msg of messages) {
      summary.scanned++;
      const messageId = String(msg.messageId);
      if (db.seenMessageIds[messageId]) { summary.skipped++; continue; }
      const hasAttachment = msg.hasAttachment === '1' || msg.hasAttachment === 1 || msg.hasAttachment === true;
      if (!hasAttachment) { db.seenMessageIds[messageId] = 'no-attachment'; continue; }

      const info = await zoho.getAttachmentInfo(accountId, folderId, messageId);
      const attachments = (info && info.attachments) || [];
      const cvFiles = [];
      for (const att of attachments) {
        if (!isCvFile(att.attachmentName)) continue;
        if (Number(att.attachmentSize || 0) > MAX_ATTACHMENT_BYTES) continue;
        const buf = await zoho.downloadAttachment(accountId, folderId, messageId, att.attachmentId);
        const fileName = `${messageId}-${safeFileName(att.attachmentName)}`;
        fs.writeFileSync(path.join(CV_DIR, fileName), buf);
        cvFiles.push({ name: att.attachmentName, size: Number(att.attachmentSize || buf.length), file: fileName });
      }

      if (cvFiles.length) {
        db.candidates.unshift({
          id: messageId,
          from: msg.fromAddress || msg.sender || '',
          fromName: msg.senderName || '',
          subject: msg.subject || '(بدون موضوع)',
          summary: msg.summary || '',
          receivedTime: Number(msg.receivedTime) || Date.now(),
          attachments: cvFiles,
          source: summary.mailbox,
          status: 'new',
        });
        db.seenMessageIds[messageId] = 'imported';
        summary.imported++;
      } else {
        db.seenMessageIds[messageId] = 'no-cv';
      }
      saveDb(db); // persist incrementally so a crash never re-imports
    }

    if (messages.length < pageSize) break;
    start += pageSize;
  }

  db.lastSync = Date.now();
  db.lastSyncError = null;
  saveDb(db);
  return summary;
}

module.exports = { syncOnce, isCvFile, CV_EXTENSIONS };
