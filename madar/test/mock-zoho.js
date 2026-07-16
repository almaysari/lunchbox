// In-process mock of the Zoho Mail API used by demo mode AND the test suite.
//
// It reproduces, faithfully to the documented behaviour, the scenarios the
// real organization presents:
//   * 20 shared mailboxes under Groups (two domains) — NOT in /api/accounts
//   * aliases (+N), access levels, moderation queues, members/moderators
//   * one admin user mailbox that IS in /api/accounts and fully readable
//   * info@ additionally exposed with an org-level accountId whose messages
//     ARE readable (fixture for the "API allows message read" scenario)
//   * scan@ metadata-only (folders request rejected)
//   * groupId used as accountId → literal {"Invalid Account ID"} error
const http = require('http');
const fs = require('fs');
const path = require('path');

const ZOID = '80000001';
const ADMIN_ACCOUNT_ID = '5001000001';
const INFO_ORG_ACCOUNT_ID = '5001000777';

const baseline = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'expected-mailboxes.json'), 'utf8'));

const GROUPS = baseline.map((b, i) => ({
  zgid: String(600100 + i),
  groupName: b.name,
  emailId: b.address,
  isCollaborativeInbox: true,
  accessLevel: b.accessLevel === 'only_moderators' ? 'Only Moderators'
    : b.accessLevel === 'organization_members' ? 'Organization Members' : 'Everyone',
  pendingModerationCount: b.moderationCount || 0,
  aliasList: b.address === 'info@exoticcolors.org' ? ['contact@exoticcolors.org', 'welcome@exoticcolors.org'] : [],
  members: [
    { memberEmailId: 'm.almaysari@exoticcolors.org', role: 'moderator' },
    { memberEmailId: 'staff1@exoticcolors.org', role: 'member' },
  ],
}));

function demoMessages(prefix, n) {
  const out = [];
  for (let i = 1; i <= n; i++) {
    out.push({
      messageId: `${prefix}${1000 + i}`,
      messageIdHeader: `<${prefix}${1000 + i}@mock.zoho>`,
      threadId: `t${prefix}${i % 3}`,
      fromAddress: `sender${i}@example.com`,
      senderName: `Sender ${i}`,
      toAddress: 'info@exoticcolors.org',
      subject: `Demo message ${i} (${prefix})`,
      summary: `This is the summary of demo message number ${i}.`,
      receivedTime: String(1784200000000 - i * 3600000),
      hasAttachment: i % 3 === 0 ? '1' : '0',
    });
  }
  return out;
}
// info@ has 250 messages so partial-backfill / resume / cancellation paths are exercised
const MESSAGES = { [ADMIN_ACCOUNT_ID]: demoMessages('a', 12), [INFO_ORG_ACCOUNT_ID]: demoMessages('g', 250) };
const PDF = Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF', 'latin1');

function startMockZoho(port = 0) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://mock');
    const p = url.pathname;
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    const ok = data => send(200, { status: { code: 200, description: 'success' }, data });
    const invalidAccount = () => send(400, { status: { code: 400, description: 'Invalid Account ID' }, data: { errorCode: 'INVALID_ACCOUNT_ID' } });

    if (p === '/oauth/v2/token') {
      return send(200, { access_token: 'mock-access-token', refresh_token: 'mock-refresh-token', expires_in: 3600 });
    }
    if (p === '/api/accounts') {
      return ok([{
        accountId: ADMIN_ACCOUNT_ID,
        accountDisplayName: 'Org Admin',
        mailboxAddress: 'm.almaysari@exoticcolors.org',
        primaryEmailAddress: 'm.almaysari@exoticcolors.org',
        emailAddress: [{ mailId: 'm.almaysari@exoticcolors.org', isPrimary: true }],
      }]);
    }
    if (p === '/api/organization') return ok({ zoid: ZOID, orgName: 'Exotic Colors' });
    if (p === `/api/organization/${ZOID}/accounts`) {
      return ok([
        { accountId: ADMIN_ACCOUNT_ID, primaryEmailAddress: 'm.almaysari@exoticcolors.org', role: 'super_admin' },
        // Fixture scenario: one shared mailbox exposed with an org-level accountId.
        { accountId: INFO_ORG_ACCOUNT_ID, primaryEmailAddress: 'info@exoticcolors.org', role: 'shared' },
      ]);
    }
    if (p === `/api/organization/${ZOID}/groups`) return ok(GROUPS);
    let m;
    if ((m = p.match(new RegExp(`^/api/organization/${ZOID}/groups/(\\d+)$`)))) {
      const g = GROUPS.find(x => x.zgid === m[1]);
      return g ? ok(g) : send(404, { status: { code: 404, description: 'Group not found' } });
    }
    if ((m = p.match(new RegExp(`^/api/organization/${ZOID}/groups/(\\d+)/messages$`)))) {
      const g = GROUPS.find(x => x.zgid === m[1]);
      if (!g) return send(404, { status: { code: 404, description: 'Group not found' } });
      // Moderation queue ONLY — never the mailbox archive.
      return ok(Array.from({ length: g.pendingModerationCount }, (_, i) => ({
        messageId: `mod-${g.zgid}-${i + 1}`, fromAddress: `held${i + 1}@example.com`,
        subject: `Held for moderation #${i + 1}`, receivedTime: String(1784200000000 - i * 60000),
      })));
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/folders$/))) {
      const id = m[1];
      if (id === ADMIN_ACCOUNT_ID || id === INFO_ORG_ACCOUNT_ID) {
        return ok([
          { folderId: id + '-f1', folderName: 'Inbox', folderType: 'Inbox' },
          { folderId: id + '-f2', folderName: 'Sent', folderType: 'Sent' },
        ]);
      }
      return invalidAccount(); // any groupId used as accountId → literal documented error
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/messages\/view$/))) {
      const id = m[1];
      if (!MESSAGES[id]) return invalidAccount();
      const start = Number(url.searchParams.get('start') || 1);
      const limit = Number(url.searchParams.get('limit') || 100);
      const folderId = url.searchParams.get('folderId') || '';
      const all = folderId.endsWith('-f2') ? [] : MESSAGES[id];
      return ok(all.slice(start - 1, start - 1 + limit));
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/folders\/[^/]+\/messages\/([^/]+)\/content$/))) {
      if (!MESSAGES[m[1]]) return invalidAccount();
      return ok({ messageId: m[2], content: `<p>Full HTML body of message <b>${m[2]}</b> from the mock Zoho API.</p>` });
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/folders\/[^/]+\/messages\/([^/]+)\/attachmentinfo$/))) {
      if (!MESSAGES[m[1]]) return invalidAccount();
      const msg = MESSAGES[m[1]].find(x => x.messageId === m[2]);
      return ok({ attachments: msg && msg.hasAttachment === '1' ? [{ attachmentId: 'att-' + m[2], attachmentName: `document-${m[2]}.pdf`, attachmentSize: PDF.length, attachmentType: 'application/pdf' }] : [] });
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/folders\/[^/]+\/messages\/[^/]+\/attachments\/[^/]+$/))) {
      if (!MESSAGES[m[1]]) return invalidAccount();
      res.writeHead(200, { 'Content-Type': 'application/pdf' });
      return res.end(PDF);
    }
    send(404, { status: { code: 404, description: 'URL Rule is not configured' } });
  });

  // scan@ scenario: metadata visible in groups, folders probe rejected — the
  // generic invalidAccount above covers it since scan@ has no account id.
  server.unref(); // never keep the process alive (tests / demo shutdown)
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve(server.address().port)));
}

module.exports = { startMockZoho, ZOID, ADMIN_ACCOUNT_ID, INFO_ORG_ACCOUNT_ID };
