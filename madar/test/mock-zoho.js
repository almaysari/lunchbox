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
//   * mailboxId/zgid used as accountId → literal observed rejection
//     (404 "Invalid Input" / "Account id N is invalid")
const http = require('http');
const fs = require('fs');
const path = require('path');

const ZOID = '80000001';
const ADMIN_ACCOUNT_ID = '5001000001';
const INFO_ORG_ACCOUNT_ID = '5001000777';

const baseline = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'expected-mailboxes.json'), 'utf8'));

// Field names mirror the LIVE tenant responses (observed evidence): mail-enabled
// groups carry name/emailId/mbtype:"2"/mailboxId/accessType/mailModerationcount/
// mailGroupMemberList; IAM-only department groups have no emailId at all.
const GROUPS = baseline.map((b, i) => ({
  zgid: 600100 + i,
  name: b.name,
  emailId: b.address,
  mbtype: '2',
  mailboxId: 9990000000 + i,
  accessType: b.accessLevel === 'only_moderators' ? 'Moderated'
    : b.accessLevel === 'organization_members' ? 'Organization Members' : 'Public',
  streamsEnabled: false,
  mailModerationcount: b.moderationCount || 0,
  aliasList: b.address === 'info@exoticcolors.org' ? ['contact@exoticcolors.org', 'welcome@exoticcolors.org'] : [],
  mailGroupMemberList: [
    { role: 'moderator', status: 'active', memberEmailId: 'm.almaysari@exoticcolors.org' },
    { role: 'member', status: 'active', memberEmailId: 'staff1@exoticcolors.org' },
  ],
}));
const IAM_GROUPS = ['Senior Management Department', 'Operation Department', 'Project Department', 'IT Department']
  .map((n, i) => ({
    zgid: 600090 + i, name: n, iamGroupExist: true, groupMemberCount: 2,
    mailGroupMemberList: [{ role: 'moderator', status: 'active', memberEmailId: 'm.almaysari@exoticcolors.org' }],
  }));
const ALL_GROUPS = [...IAM_GROUPS, ...GROUPS].sort((a, b) => a.zgid - b.zgid);

function demoMessages(prefix, n) {
  const out = [];
  for (let i = 1; i <= n; i++) {
    out.push({
      messageId: `${prefix}${1000 + i}`,
      // NOTE: real Zoho messages/view returns NO RFC Message-ID header — the
      // canonical identity is the v3 fingerprint, not a Message-ID.
      threadId: `t${prefix}${i % 3}`,
      fromAddress: `sender${i}@example.com`,
      senderName: `Sender ${i}`,
      // one admin message is addressed to a shared mailbox — exercises live
      // routing of member copies into the group's registry mailbox
      toAddress: prefix === 'a' && i === 1 ? 'hr@exoticcolors.org' : 'info@exoticcolors.org',
      subject: `Demo message ${i} (${prefix})`,
      summary: `This is the summary of demo message number ${i}.`,
      receivedTime: String(1784200000000 - i * 3600000),
      sentDateInGMT: String(1783000000000 - i * 3600000), // sent time (fingerprint anchor)
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
    // Literal rejection observed on the live tenant when a non-account id is
    // used against the accounts-scoped family (mailboxId or zgid).
    const invalidAccount = (id) => send(404, { status: { code: 404, description: 'Invalid Input' }, data: { moreInfo: `Account id ${id} is invalid` } });

    if (p === '/oauth/v2/token') {
      return send(200, { access_token: 'mock-access-token', refresh_token: 'mock-refresh-token', expires_in: 3600 });
    }
    if (p === '/api/accounts') {
      return ok([{
        accountId: ADMIN_ACCOUNT_ID,
        accountDisplayName: 'Org Admin',
        role: 'super_admin',
        policyId: { zoid: Number(ZOID) }, // real tenants expose the org id here
        mailboxAddress: 'm.almaysari@exoticcolors.org',
        primaryEmailAddress: 'm.almaysari@exoticcolors.org',
        emailAddress: [{ mailId: 'm.almaysari@exoticcolors.org', isPrimary: true }],
      }]);
    }
    // Observed in production: this endpoint rejects the token even for a
    // super admin — discovery must survive it via the accounts fallback.
    if (p === '/api/organization') {
      return send(401, [2, { msg: 'Error while processing!', status: '401', authFail: 'true', errorCode: 'INVALID_OAUTHSCOPE' }]);
    }
    if (p === `/api/organization/${ZOID}/accounts`) {
      return ok([
        {
          accountId: ADMIN_ACCOUNT_ID, primaryEmailAddress: 'm.almaysari@exoticcolors.org', role: 'super_admin',
          // Real tenants list every group the user belongs to — discovery's
          // second source when the paged /groups endpoint stops early.
          groupList: GROUPS.map(g => ({ zgid: g.zgid, name: g.name, emailId: g.emailId, role: 'moderator' })),
          iamGroupList: IAM_GROUPS.map(g => ({ zgid: g.zgid, name: g.name, role: 'member' })),
        },
        // Fixture scenario: one shared mailbox exposed with an org-level accountId.
        { accountId: INFO_ORG_ACCOUNT_ID, primaryEmailAddress: 'info@exoticcolors.org', role: 'shared' },
      ]);
    }
    if (p === `/api/organization/${ZOID}/groups`) {
      // Mirrors production behaviour observed in live evidence: the endpoint
      // returns an OBJECT {count, groups, domains}, pages by 10 lowest zgids,
      // and (as observed) does not advance with `start` — discovery must
      // detect the stagnant page and fall back to membership-derived groups.
      const page = ALL_GROUPS.slice(0, 10);
      return ok({ count: page.length, groups: page, domains: ['exoticcolors.org', 'thetaurus.world'] });
    }
    let m;
    if ((m = p.match(new RegExp(`^/api/organization/${ZOID}/groups/(\\d+)$`)))) {
      const g = ALL_GROUPS.find(x => String(x.zgid) === m[1]);
      return g ? ok(g) : send(404, { status: { code: 404, description: 'Group not found' } });
    }
    if ((m = p.match(new RegExp(`^/api/organization/${ZOID}/groups/(\\d+)/messages$`)))) {
      const g = ALL_GROUPS.find(x => String(x.zgid) === m[1]);
      if (!g) return send(404, { status: { code: 404, description: 'Group not found' } });
      // Moderation queue ONLY — never the mailbox archive.
      return ok(Array.from({ length: g.mailModerationcount || 0 }, (_, i) => ({
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
      return invalidAccount(id); // non-account id → literal observed rejection
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/messages\/view$/))) {
      const id = m[1];
      if (!MESSAGES[id]) return invalidAccount(id);
      const start = Number(url.searchParams.get('start') || 1);
      const limit = Number(url.searchParams.get('limit') || 100);
      const folderId = url.searchParams.get('folderId') || '';
      const all = folderId.endsWith('-f2') ? [] : MESSAGES[id];
      return ok(all.slice(start - 1, start - 1 + limit));
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/folders\/[^/]+\/messages\/([^/]+)\/content$/))) {
      if (!MESSAGES[m[1]]) return invalidAccount(m[1]);
      return ok({ messageId: m[2], content: `<p>Full HTML body of message <b>${m[2]}</b> from the mock Zoho API.</p>` });
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/folders\/[^/]+\/messages\/([^/]+)\/attachmentinfo$/))) {
      if (!MESSAGES[m[1]]) return invalidAccount(m[1]);
      const msg = MESSAGES[m[1]].find(x => x.messageId === m[2]);
      return ok({ attachments: msg && msg.hasAttachment === '1' ? [{ attachmentId: 'att-' + m[2], attachmentName: `document-${m[2]}.pdf`, attachmentSize: PDF.length, attachmentType: 'application/pdf' }] : [] });
    }
    if ((m = p.match(/^\/api\/accounts\/([^/]+)\/folders\/[^/]+\/messages\/[^/]+\/attachments\/[^/]+$/))) {
      if (!MESSAGES[m[1]]) return invalidAccount(m[1]);
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

module.exports = { startMockZoho, ZOID, ADMIN_ACCOUNT_ID, INFO_ORG_ACCOUNT_ID, _messages: MESSAGES };
