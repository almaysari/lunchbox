#!/usr/bin/env node
// People Desk — Zoho Mail shared-mailbox diagnostic.
//
// Purpose: produce HARD EVIDENCE (raw API responses, no assumptions) about
// whether a shared/group mailbox (e.g. hr@company.com) can be read directly
// through official Zoho APIs, and with which identifier (accountId / zoid /
// groupId). Read-only: performs GET requests only, changes nothing.
//
// Usage:
//   1. Create a "Self Client" at https://api-console.zoho.com and generate a
//      code (validity 10 min) with EXACTLY these scopes:
//        ZohoMail.accounts.READ,ZohoMail.folders.READ,ZohoMail.messages.READ,ZohoMail.organization.accounts.READ,ZohoMail.organization.groups.READ
//   2. Run:  node scripts/diagnose.js
//      (answers can also be passed via env: ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET,
//       ZOHO_SELF_CLIENT_CODE, ZOHO_ACCOUNTS_BASE, ZOHO_MAIL_BASE, TARGET_MAILBOX)
//   3. Send back the generated file: data/diagnose-report.json
//      (it contains NO tokens — they are stripped before writing).

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const OUT_DIR = path.join(__dirname, '..', 'data');
const OUT_FILE = path.join(OUT_DIR, 'diagnose-report.json');
const report = { startedAt: new Date().toISOString(), env: {}, tests: [], conclusions: [] };

function ask(q, envKey) {
  if (process.env[envKey]) return Promise.resolve(process.env[envKey]);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(r => rl.question(q, a => { rl.close(); r(a.trim()); }));
}

async function record(name, question, fn) {
  const entry = { name, question, at: new Date().toISOString() };
  try {
    const { url, status, body } = await fn();
    entry.url = url; entry.status = status;
    entry.body = typeof body === 'string' && body.length > 60000 ? body.slice(0, 60000) + '…[truncated]' : body;
    entry.ok = status >= 200 && status < 300;
  } catch (err) {
    entry.ok = false;
    entry.error = String(err.message || err);
  }
  report.tests.push(entry);
  console.log(`\n[${entry.ok ? 'OK ' : 'FAIL'}] ${name}  ${entry.url || ''}  status=${entry.status ?? '-'}`);
  if (!entry.ok) console.log('       ' + (entry.error || JSON.stringify(entry.body).slice(0, 300)));
  return entry;
}

async function main() {
  console.log('=== People Desk / Zoho shared-mailbox diagnostic (read-only) ===\n');
  const accountsBase = (await ask('Zoho accounts base [https://accounts.zoho.com]: ', 'ZOHO_ACCOUNTS_BASE')) || 'https://accounts.zoho.com';
  const mailBase = (await ask('Zoho mail API base [https://mail.zoho.com]: ', 'ZOHO_MAIL_BASE')) || 'https://mail.zoho.com';
  const clientId = await ask('Self Client - Client ID: ', 'ZOHO_CLIENT_ID');
  const clientSecret = await ask('Self Client - Client Secret: ', 'ZOHO_CLIENT_SECRET');
  const code = await ask('Self Client - Generated Code: ', 'ZOHO_SELF_CLIENT_CODE');
  const target = ((await ask('Target mailbox [hr@exoticcolors.org]: ', 'TARGET_MAILBOX')) || 'hr@exoticcolors.org').toLowerCase();
  report.env = { accountsBase, mailBase, target };

  // --- Token exchange (self client) ---
  let token = null;
  await record('oauth.exchange', 'Can the self-client code be exchanged for an access token?', async () => {
    const url = accountsBase + '/oauth/v2/token';
    const res = await fetch(url, {
      method: 'POST',
      body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: clientId, client_secret: clientSecret }),
    });
    const body = await res.json();
    if (body.access_token) { token = body.access_token; }
    // strip secrets from the report
    const redacted = { ...body };
    for (const k of ['access_token', 'refresh_token', 'id_token']) if (redacted[k]) redacted[k] = '[REDACTED len=' + String(body[k]).length + ']';
    return { url, status: res.status, body: redacted };
  });
  if (!token) { finish('Token exchange failed — nothing else can be tested.'); return; }

  const get = async (pathname) => {
    const url = mailBase + pathname;
    const res = await fetch(url, { headers: { Authorization: 'Zoho-oauthtoken ' + token } });
    let body; const text = await res.text();
    try { body = JSON.parse(text); } catch { body = text; }
    return { url, status: res.status, body };
  };

  // --- Q1: which mailboxes does the Mail API expose to this user? ---
  const accResp = await record('mail.accounts', 'GET /api/accounts — does the target mailbox appear with its own accountId?', () => get('/api/accounts'));
  const accounts = (accResp.body && accResp.body.data) || [];
  const accountSummary = accounts.map(a => ({
    accountId: a.accountId,
    accountName: a.accountName,
    mailboxAddress: a.mailboxAddress,
    primaryEmailAddress: a.primaryEmailAddress,
    emailAddress: a.emailAddress,
    accountType: a.accountType,
    role: a.role,
    type: a.type,
    isDefault: a.isDefault,
    status: a.status,
  }));
  report.conclusions.push({ visibleMailboxes: accountSummary });
  const targetAccount = accounts.find(a =>
    String(a.mailboxAddress || '').toLowerCase() === target ||
    String(a.primaryEmailAddress || '').toLowerCase() === target ||
    (Array.isArray(a.emailAddress) && a.emailAddress.some(e => String(e.mailId || e).toLowerCase() === target)));

  // --- Q2: organization + groups — what does Zoho classify the target as? ---
  const orgResp = await record('org.details', 'GET /api/organization — retrieve zoid (org id)', () => get('/api/organization'));
  let zoid = orgResp.body && orgResp.body.data && (orgResp.body.data.zoid || orgResp.body.data.zgid || orgResp.body.data.orgId);
  if (!zoid && Array.isArray(orgResp.body && orgResp.body.data)) zoid = orgResp.body.data[0] && (orgResp.body.data[0].zoid || orgResp.body.data[0].orgId);

  let targetGroup = null;
  if (zoid) {
    const grpResp = await record('org.groups', `GET /api/organization/${zoid}/groups — is the target listed as a group, and of what type?`, () => get(`/api/organization/${zoid}/groups`));
    const groups = (grpResp.body && grpResp.body.data) || [];
    targetGroup = groups.find(g =>
      String(g.emailId || g.groupEmailId || g.mailId || '').toLowerCase() === target ||
      (Array.isArray(g.emailIds) && g.emailIds.some(e => String(e).toLowerCase() === target)));
    report.conclusions.push({ targetGroupRaw: targetGroup || 'NOT FOUND in groups list', groupCount: groups.length });

    if (targetGroup) {
      const gid = targetGroup.zgid || targetGroup.groupId || targetGroup.id;
      await record('org.group.details', `GET /api/organization/${zoid}/groups/${gid} — full group settings/type`, () => get(`/api/organization/${zoid}/groups/${gid}`));
      await record('org.group.moderation', `GET /api/organization/${zoid}/groups/${gid}/messages — official Groups API message list (moderation queue): what does it actually return?`, () => get(`/api/organization/${zoid}/groups/${gid}/messages?start=0&limit=25`));
      // The "Invalid Account ID" question: what happens when the groupId is used as an accountId?
      await record('mail.groupIdAsAccountId.folders', `GET /api/accounts/${gid}/folders — exact error when groupId is used as accountId`, () => get(`/api/accounts/${gid}/folders`));
      await record('mail.groupIdAsAccountId.messages', `GET /api/accounts/${gid}/messages/view — exact error when groupId is used as accountId`, () => get(`/api/accounts/${gid}/messages/view?limit=10`));
    }

    // Admin view: do org user accounts include the target as a user account?
    const orgAccResp = await record('org.accounts', `GET /api/organization/${zoid}/accounts — org-level account list (admin): does the target appear here with an accountId?`, () => get(`/api/organization/${zoid}/accounts?start=0&limit=200`));
    const orgAccounts = (orgAccResp.body && orgAccResp.body.data) || [];
    const targetOrgAccount = Array.isArray(orgAccounts)
      ? orgAccounts.find(a => JSON.stringify(a).toLowerCase().includes(target)) : null;
    report.conclusions.push({ targetInOrgAccounts: targetOrgAccount || 'NOT FOUND in org accounts' });
    if (targetOrgAccount && targetOrgAccount.accountId) {
      await record('mail.orgAccountId.messages', `GET /api/accounts/${targetOrgAccount.accountId}/messages/view — can the target be read via its org-level accountId?`, () => get(`/api/accounts/${targetOrgAccount.accountId}/messages/view?limit=10`));
    }
  } else {
    report.conclusions.push({ note: 'zoid could not be determined — org-level tests skipped. Check org.details raw body.' });
  }

  // --- Q3: prove what IS readable — folders + first message page per visible account ---
  for (const a of accounts) {
    const fResp = await record(`mail.folders.${a.accountId}`, `GET folders of visible mailbox ${a.mailboxAddress || a.primaryEmailAddress}`, () => get(`/api/accounts/${a.accountId}/folders`));
    const folders = (fResp.body && fResp.body.data) || [];
    const inbox = folders.find(f => String(f.folderType || f.folderName).toLowerCase().includes('inbox')) || folders[0];
    if (inbox) {
      await record(`mail.messages.${a.accountId}`, `GET first page of messages in ${a.mailboxAddress || a.primaryEmailAddress} / ${inbox.folderName}`, () => get(`/api/accounts/${a.accountId}/messages/view?folderId=${inbox.folderId}&limit=5`));
    }
  }

  // --- Verdict (mechanical, from evidence above) ---
  report.conclusions.push({
    directOAuthAccessToTarget: targetAccount
      ? { verdict: 'YES — target appears in /api/accounts with accountId ' + targetAccount.accountId, account: targetAccount }
      : 'NO — target does not appear in /api/accounts for this OAuth user (see visibleMailboxes and group tests above)',
  });
  finish();
}

function finish(note) {
  if (note) report.conclusions.push({ note });
  report.finishedAt = new Date().toISOString();
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(report, null, 2));
  console.log('\n=== Done. Full evidence written to: ' + OUT_FILE + ' ===');
  console.log('The report contains no tokens. Send this file back for analysis.');
}

main().catch(err => { console.error(err); finish('Fatal: ' + String(err.message || err)); });
