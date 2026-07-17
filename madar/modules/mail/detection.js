// Detection Engine — organization-wide discovery + per-mailbox capability probes.
//
// Principles:
//  * Zoho API responses are the ONLY source of truth at runtime.
//  * The expected-mailboxes baseline (test/fixtures) is a validation reference,
//    never a data source.
//  * Every conclusion carries literal (sanitized) API evidence.
//  * Read-only: GET requests only.
const { q, one } = require('../../core/db');

const lc = s => String(s || '').toLowerCase().trim();

// PII-safe evidence for message-level probes: status + shape only —
// never subjects, senders, recipients, bodies or attachment names.
function sanitizeMessageList(result) {
  const data = result.body && result.body.data;
  return {
    url: result.url, status: result.status,
    count: Array.isArray(data) ? data.length : null,
    fieldsPresent: Array.isArray(data) && data[0] ? Object.keys(data[0]).sort() : [],
    error: result.status >= 400 ? sanitize(result).body : undefined,
  };
}
function sanitizeContent(result) {
  const c = result.body && result.body.data && result.body.data.content;
  return { url: result.url, status: result.status, hasContent: Boolean(c), contentLength: c ? String(c).length : 0 };
}
function sanitizeAttachmentInfo(result) {
  const atts = (((result.body || {}).data) || {}).attachments;
  return {
    url: result.url, status: result.status,
    attachmentCount: Array.isArray(atts) ? atts.length : null,
    // sizes/types only — filenames may be sensitive
    shapes: Array.isArray(atts) ? atts.slice(0, 3).map(a => ({ size: a.attachmentSize, type: a.attachmentType })) : [],
    error: result.status >= 400 ? sanitize(result).body : undefined,
  };
}

function sanitize(result) {
  // Evidence stored in DB: keep url/status/body but cap body size.
  const body = typeof result.body === 'string'
    ? result.body.slice(0, 4000)
    : JSON.parse(JSON.stringify(result.body ?? null, (k, v) =>
        typeof v === 'string' && v.length > 2000 ? v.slice(0, 2000) + '…' : v));
  return { url: result.url, status: result.status, body };
}

// Live tenant payloads for accounts/groups carry personal data (phone numbers,
// home addresses, dates of birth). Stored evidence keeps only the structural
// fields discovery actually reasons about — allowlist, never blocklist.
function sanitizeAccountRecord(a) {
  if (!a || typeof a !== 'object') return a;
  return {
    accountId: a.accountId, zuid: a.zuid, role: a.role, iamUserRole: a.iamUserRole,
    status: a.status, mailboxStatus: a.mailboxStatus,
    mailboxAddress: a.mailboxAddress, primaryEmailAddress: a.primaryEmailAddress,
    emailAddress: Array.isArray(a.emailAddress)
      ? a.emailAddress.map(e => ({ mailId: e.mailId, isPrimary: e.isPrimary, isAlias: e.isAlias })) : undefined,
    emailAlias: a.emailAlias,
    policyId: a.policyId && a.policyId.zoid ? { zoid: a.policyId.zoid } : undefined,
    groupList: Array.isArray(a.groupList)
      ? a.groupList.map(g => ({ zgid: g.zgid, name: g.name, emailId: g.emailId, role: g.role })) : undefined,
    iamGroupList: Array.isArray(a.iamGroupList)
      ? a.iamGroupList.map(g => ({ zgid: g.zgid, name: g.name, emailId: g.emailId, role: g.role })) : undefined,
  };
}
function sanitizeGroupRecord(g) {
  if (!g || typeof g !== 'object') return g;
  return {
    zgid: g.zgid, name: g.name || g.groupName, emailId: g.emailId, mbtype: g.mbtype,
    mailboxId: g.mailboxId, accessType: g.accessType, accessLevel: g.accessLevel,
    isCollaborativeInbox: g.isCollaborativeInbox, streamsEnabled: g.streamsEnabled,
    groupMemberCount: g.groupMemberCount,
    mailModerationcount: g.mailModerationcount, pendingModerationCount: g.pendingModerationCount,
    aliasList: g.aliasList,
    members: extractMembers(g), // business email + role only
  };
}
function sanitizeAccountsResponse(result) {
  const data = result.body && result.body.data;
  return { url: result.url, status: result.status,
    body: result.status >= 400 ? sanitize(result).body
      : { count: Array.isArray(data) ? data.length : null,
          data: Array.isArray(data) ? data.map(sanitizeAccountRecord) : data } };
}

// Zoho returns the group list either as data:[...] (docs) or as
// data:{count,groups:[...],domains:[...]} (observed live on the tenant).
function parseGroupsBody(body) {
  const d = body && body.data;
  if (Array.isArray(d)) return d;
  if (d && Array.isArray(d.groups)) return d.groups;
  return [];
}

function extractEmails(value) {
  // Zoho group/account payloads vary; collect every email-looking string field.
  const found = new Set();
  (function walk(v) {
    if (typeof v === 'string') {
      const m = v.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g);
      if (m) m.forEach(e => found.add(lc(e)));
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  })(value);
  return [...found];
}

// ---- classify a raw Zoho group object ----
function classifyGroup(g) {
  const raw = JSON.stringify(g).toLowerCase();
  // Live tenant evidence: mail-enabled groups (the Admin Console "Shared
  // Mailbox" entries) carry mbtype:"2" + a mailboxId + an emailId. IAM-only
  // org groups (departments) have no emailId at all.
  if (!groupEmail(g)) return 'org_group';
  const looksShared =
    g.isCollaborativeInbox === true || g.isCollaborativeInbox === 'true' ||
    g.isSharedMailbox === true || g.isSharedMailbox === 'true' ||
    String(g.mbtype) === '2' || g.mailboxId != null ||
    lc(g.groupType).includes('shared') || lc(g.mailboxType).includes('shared') ||
    raw.includes('"collaborativeinbox":true') || raw.includes('sharedmailbox');
  const looksStream = g.isStreamGroup === true || g.streamsEnabled === true || lc(g.groupType).includes('stream');
  if (looksShared) return 'shared_mailbox';
  if (looksStream) return 'stream_group';
  return 'distribution_list';
}

function groupEmail(g) {
  const v = lc(g.emailId || g.groupEmailId || g.mailId || '');
  return v.includes('@') ? v : ''; // a group name is never an address
}

function groupAliases(g) {
  const primary = groupEmail(g);
  const all = new Set();
  for (const key of ['aliasList', 'aliases', 'emailIds', 'groupAliases']) {
    const v = g[key];
    if (Array.isArray(v)) v.forEach(a => all.add(lc(typeof a === 'string' ? a : a.alias || a.mailId || a.emailId || '')));
  }
  all.delete(''); all.delete(primary);
  return [...all];
}

function accessLevel(g) {
  const v = lc(g.accessLevel || g.accessType || g.whoCanSend || '');
  if (v.includes('moderat')) return 'only_moderators';
  if (v.includes('org')) return 'organization_members';
  if (v.includes('every') || v.includes('all') || v === 'public') return 'everyone';
  return v || '';
}

// ---- organization-wide discovery ----
async function discoverOrganization(zoho) {
  const evidence = {};
  const out = { mailboxes: [], evidence };

  // 1) Mailboxes visible to the OAuth user directly.
  const accResp = await zoho.getAccounts();
  evidence.accounts = sanitizeAccountsResponse(accResp); // PII-reduced (allowlist)
  const accounts = (accResp.body && accResp.body.data) || [];

  // 2) Organization id — two evidence-based sources:
  //    a) GET /api/organization (may fail with INVALID_OAUTHSCOPE on real
  //       tenants even for super admins — observed in production evidence)
  //    b) fallback: the /api/accounts payload itself carries the org id
  //       (policyId.zoid) — proven by live evidence on the company tenant.
  const orgResp = await zoho.getOrganization();
  evidence.organization = sanitize(orgResp);
  let zoid = null;
  const od = orgResp.body && orgResp.body.data;
  if (od) zoid = od.zoid || od.zgid || od.orgId || (Array.isArray(od) && od[0] && (od[0].zoid || od[0].orgId)) || null;
  if (!zoid) {
    for (const a of accounts) {
      const cand = (a.policyId && a.policyId.zoid) || a.zoid || a.orgId || null;
      if (cand) { zoid = String(cand); evidence.zoidSource = 'accounts.policyId.zoid (fallback — /api/organization unavailable)'; break; }
    }
  } else {
    evidence.zoidSource = '/api/organization';
  }

  // 3) Org-level account list (admin scope) — some entities may only appear here.
  let orgAccounts = [];
  if (zoid) {
    const oaResp = await zoho.getOrgAccounts(zoid);
    evidence.orgAccounts = sanitizeAccountsResponse(oaResp); // PII-reduced (allowlist)
    orgAccounts = (oaResp.body && oaResp.body.data) || [];
    if (!Array.isArray(orgAccounts)) orgAccounts = [];
  }

  // 4) Groups — where shared mailboxes live (Admin Console → Groups → Shared Mailbox).
  //    Live evidence showed the endpoint pages its results (first call returned
  //    only the 10 lowest zgids of ~30 groups), so we paginate until a short or
  //    stagnant page, then union with a second evidence source: every group the
  //    org accounts list their memberships in (groupList/iamGroupList).
  let groups = [];
  if (zoid) {
    const PAGE = 100;
    const seenZgids = new Set();
    const pages = [];
    for (let start = 0, page = 0; page < 20; page++) {
      const gResp = await zoho.getGroups(zoid, start, PAGE);
      pages.push({ url: gResp.url, status: gResp.status });
      if (gResp.status !== 200) { if (page === 0) evidence.groupsError = sanitize(gResp); break; }
      const batch = parseGroupsBody(gResp.body);
      const fresh = batch.filter(g => g && g.zgid != null && !seenZgids.has(String(g.zgid)));
      if (!fresh.length) break; // short page, or server ignored `start` and repeated itself
      fresh.forEach(g => { seenZgids.add(String(g.zgid)); groups.push(g); });
      if (batch.length < PAGE) break;
      start += batch.length;
    }
    evidence.groups = {
      pages, totalFetched: groups.length,
      body: { data: groups.map(sanitizeGroupRecord) }, // PII-reduced (allowlist)
    };

    // Second source (same tenant responses, no extra scope): group memberships.
    const fromMembership = new Map();
    for (const a of orgAccounts) {
      for (const list of [a.groupList, a.iamGroupList]) {
        if (!Array.isArray(list)) continue;
        for (const g of list) {
          const zg = g && g.zgid != null ? String(g.zgid) : '';
          if (zg && !seenZgids.has(zg) && !fromMembership.has(zg)) fromMembership.set(zg, g);
        }
      }
    }
    evidence.groupsFromMembership = [...fromMembership.values()]
      .map(g => ({ zgid: g.zgid, name: g.name, emailId: g.emailId, source: 'orgAccounts.groupList' }));
    for (const [zg, stub] of fromMembership) {
      // Fetch the authoritative group object; fall back to the membership stub.
      const det = await zoho.getGroupDetails(zoid, zg);
      const detData = det && det.status === 200 && det.body && det.body.data ? det.body.data : null;
      const merged = detData ? { ...stub, ...detData } : { ...stub };
      merged.zgid = merged.zgid ?? zg;
      merged._source = detData ? 'membership+groupDetails' : 'membership_stub';
      seenZgids.add(zg);
      groups.push(merged);
    }
  }

  // Match accounts strictly by their OWN addresses. A whole-payload email walk
  // is wrong here: real org accounts embed groupList (memberships), so hr@ etc.
  // would bind to a MEMBER's accountId and probes would read the wrong mailbox.
  const accountOwnEmails = (a) => {
    const out = new Set();
    [a.mailboxAddress, a.primaryEmailAddress, a.incomingUserName].forEach(e => e && out.add(lc(e)));
    if (Array.isArray(a.emailAddress)) a.emailAddress.forEach(e => { const v = lc(typeof e === 'string' ? e : e.mailId || ''); if (v) out.add(v); });
    if (Array.isArray(a.emailAlias)) a.emailAlias.forEach(e => e && out.add(lc(e)));
    out.delete('');
    return [...out];
  };
  const findAccountFor = (email) =>
    accounts.find(a => accountOwnEmails(a).includes(email)) ||
    orgAccounts.find(a => accountOwnEmails(a).includes(email));
  const inOrgAccounts = (email) => orgAccounts.some(a => accountOwnEmails(a).includes(email));

  // Group-backed entities (shared mailboxes are the primary case here).
  for (const g of groups) {
    const email = groupEmail(g);
    if (!email) continue; // IAM-only org groups (departments) have no address
    const gid = String(g.zgid || g.groupId || g.id || '');
    const acct = findAccountFor(email);
    // Membership-derived groups already merged their /groups/{zgid} detail.
    const detail = zoid && gid && !g._source ? await zoho.getGroupDetails(zoid, gid) : null;
    const detailData = detail && detail.body && detail.body.data ? detail.body.data : g;
    const full = { ...g, ...detailData };
    out.mailboxes.push({
      address: email,
      displayName: full.name || full.groupName || '',
      detectedType: classifyGroup(full),
      orgId: zoid ? String(zoid) : null,
      providerGroupId: gid || null,
      providerAccountId: acct ? String(acct.accountId) : null,
      providerMailboxId: String((acct && acct.mailboxId) || full.mailboxId || '') || null,
      foundInOrgAccounts: inOrgAccounts(email),
      aliases: groupAliases(full),
      accessLevel: accessLevel(full),
      members: extractMembers(full),
      moderators: extractModerators(full),
      moderationCount: Number(full.mailModerationcount ?? full.pendingModerationCount ?? 0) || 0,
      evidence: {
        group: { url: g._source || 'groups[]', status: 200, body: sanitizeGroupRecord(g) },
        detail: detail ? { url: detail.url, status: detail.status, body: sanitizeGroupRecord(detailData) } : null,
      },
    });
  }

  // User mailboxes visible via /api/accounts that are NOT group-backed.
  const groupEmails = new Set(out.mailboxes.map(m => m.address));
  for (const a of accounts) {
    const email = lc(a.mailboxAddress || a.primaryEmailAddress || '');
    if (!email || groupEmails.has(email)) continue;
    out.mailboxes.push({
      address: email,
      displayName: a.accountDisplayName || a.accountName || '',
      detectedType: 'user',
      orgId: zoid ? String(zoid) : null,
      providerGroupId: null,
      providerAccountId: String(a.accountId),
      providerMailboxId: String(a.mailboxId || '') || null,
      foundInOrgAccounts: inOrgAccounts(email),
      aliases: (Array.isArray(a.emailAddress) ? a.emailAddress.map(e => lc(e.mailId || e)) : []).filter(e => e && e !== email),
      accessLevel: '',
      members: [], moderators: [], moderationCount: 0,
      evidence: { account: { url: '/api/accounts[]', status: 200, body: sanitizeAccountRecord(a) } },
    });
  }

  // Integrity checks for the discovery report
  const byAddr = {};
  for (const mb of out.mailboxes) (byAddr[mb.address] = byAddr[mb.address] || []).push(mb);
  const providerIds = {};
  for (const mb of out.mailboxes) {
    for (const pid of [mb.providerGroupId, mb.providerAccountId].filter(Boolean)) {
      (providerIds[pid] = providerIds[pid] || []).push(mb.address);
    }
  }
  const primaries = new Set(out.mailboxes.map(m => m.address));
  out.integrity = {
    sameAddressFromMultipleEndpoints: Object.entries(byAddr).filter(([, v]) => v.length > 1).map(([a]) => a),
    duplicateProviderIds: Object.entries(providerIds).filter(([, v]) => v.length > 1).map(([id, v]) => ({ id, addresses: v })),
    aliasCollisions: out.mailboxes.flatMap(m => (m.aliases || []).filter(a => primaries.has(a)).map(a => ({ alias: a, mailbox: m.address }))),
  };
  return out;
}

function extractMembers(g) {
  for (const key of ['mailGroupMemberList', 'members', 'memberList', 'groupMembers']) {
    if (Array.isArray(g[key])) {
      return g[key].map(m => ({ email: lc(typeof m === 'string' ? m : m.memberEmailId || m.mailId || m.emailId || ''), role: lc(m.role || m.memberType || 'member') }))
        .filter(m => m.email);
    }
  }
  return [];
}

function extractModerators(g) {
  const fromMembers = extractMembers(g).filter(m => m.role.includes('moderat')).map(m => m.email);
  for (const key of ['moderators', 'moderatorList']) {
    if (Array.isArray(g[key])) {
      return [...new Set([...fromMembers, ...g[key].map(m => lc(typeof m === 'string' ? m : m.memberEmailId || m.mailId || ''))])].filter(Boolean);
    }
  }
  return fromMembers;
}

// ---- per-mailbox capability probe (read-only) ----
// Never invents an API: tries the documented endpoints with every candidate id
// and records the literal outcome. Answers, per mailbox:
//   groupId? accountId? mailboxId? appears in org accounts? folders readable?
//   messages? full content? attachment info? real attachment download? Sent?
//   does the group messages endpoint expose the archive or moderation only?
async function probeCapabilities(zoho, mailbox) {
  const caps = {
    ids: {
      groupId: mailbox.providerGroupId || null,
      accountId: mailbox.providerAccountId || null,
      mailboxId: mailbox.providerMailboxId || null,
      appearsInOrgAccounts: Boolean(mailbox.foundInOrgAccounts),
    },
    folders: false, folderCount: 0, messages: false, content: false,
    attachmentInfo: null, attachmentDownload: null, sent: false, evidence: {},
  };
  const candidates = [];
  if (mailbox.providerAccountId) candidates.push({ kind: 'accountId', id: mailbox.providerAccountId });
  if (mailbox.providerMailboxId && mailbox.providerMailboxId !== mailbox.providerAccountId) {
    candidates.push({ kind: 'mailboxId', id: mailbox.providerMailboxId });
  }
  if (mailbox.providerGroupId) candidates.push({ kind: 'groupIdAsAccountId', id: mailbox.providerGroupId });

  for (const cand of candidates) {
    const f = await zoho.getFolders(cand.id);
    caps.evidence[`folders.${cand.kind}`] = sanitize(f);
    const folders = (f.body && f.body.data) || [];
    if (f.status === 200 && Array.isArray(folders) && folders.length) {
      caps.folders = true;
      caps.folderCount = folders.length;
      caps.workingId = cand.id;
      caps.workingIdKind = cand.kind;
      const inbox = folders.find(x => lc(x.folderType) === 'inbox' || lc(x.folderName) === 'inbox') || folders[0];
      const sent = folders.find(x => lc(x.folderType) === 'sent' || lc(x.folderName).includes('sent'));
      caps.sent = Boolean(sent);
      const m = await zoho.listMessages(cand.id, inbox.folderId, { limit: 3 });
      caps.evidence[`messages.${cand.kind}`] = sanitizeMessageList(m); // shape only — no PII
      const msgs = (m.body && m.body.data) || [];
      if (m.status === 200 && Array.isArray(msgs)) {
        caps.messages = true;
        if (msgs[0]) {
          // content endpoint test: status + length only, body never stored
          const c = await zoho.getMessageContent(cand.id, inbox.folderId, msgs[0].messageId);
          caps.evidence['content'] = sanitizeContent(c);
          caps.content = c.status === 200;
        }
        const withAtt = msgs.find(x => x.hasAttachment === '1' || x.hasAttachment === 1 || x.hasAttachment === true);
        if (withAtt) {
          const ai = await zoho.getAttachmentInfo(cand.id, inbox.folderId, withAtt.messageId);
          caps.evidence['attachmentInfo'] = sanitizeAttachmentInfo(ai);
          caps.attachmentInfo = ai.status === 200;
        }
        // POLICY (Live Discovery phase): attachment DOWNLOAD is never probed —
        // metadata proves the endpoint; bytes flow only in an approved pilot sync.
        caps.attachmentDownload = 'not_probed_by_policy';
      }
      break; // a working id was found — no need to try the next candidate
    }
  }

  // Group messages endpoint nature: per Zoho docs it is the MODERATION queue.
  // We verify against the mailbox's live message list when both are readable,
  // and never count it as archive access.
  if (mailbox.orgId && mailbox.providerGroupId) {
    const mod = await zoho.getGroupModeration(mailbox.orgId, mailbox.providerGroupId);
    caps.evidence['moderationQueue'] = sanitize(mod);
    caps.moderationQueueReadable = mod.status === 200;
    const modCount = Array.isArray((mod.body || {}).data) ? mod.body.data.length : null;
    caps.groupMessagesEndpoint = mod.status !== 200 ? 'unreadable'
      : (modCount === 0 || modCount === mailbox.moderationCount) && modCount !== null
        ? 'moderation_queue_only' : 'returned_data_needs_review';
  }
  return caps;
}

function chooseStrategy(mailbox, caps) {
  // confidence: high = conclusive probe result (works, or a definitive
  // documented rejection); medium = metadata only / ambiguous statuses
  const conclusiveDenial = Object.values(caps.evidence || {}).some(e => e && (e.status === 400 || e.status === 404));
  const confidence = caps.messages ? 'high' : conclusiveDenial ? 'high' : 'medium';
  if (caps.messages) return { strategy: 'mail_api', status: 'ready', confidence, detail: `Live read via ${caps.workingIdKind}=${caps.workingId}` };
  if (mailbox.detectedType === 'shared_mailbox') {
    return {
      strategy: 'ediscovery_import', status: 'no_live_api', confidence,
      detail: 'No live message read via any tested official endpoint (see evidence). ' +
              'Official paths available: admin eDiscovery/Backup export import (archive, NOT live sync)' +
              (caps.moderationQueueReadable ? ' + moderation queue (held mail only, NOT the archive)' : '') + '.',
    };
  }
  return { strategy: 'none', status: 'error', confidence, detail: 'No read path proven for this mailbox type. See evidence.' };
}

// ---- registry upsert with alias-duplicate protection (PostgreSQL) ----
async function upsertMailbox(connectionId, m, caps, choice) {
  // An alias must never become a second mailbox.
  const aliasHit = await one('SELECT mailbox_id FROM mailbox_aliases WHERE address = $1', [m.address]);
  const existing = aliasHit
    ? await one('SELECT id FROM mailboxes WHERE id = $1', [aliasHit.mailbox_id])
    : await one('SELECT id FROM mailboxes WHERE address = $1', [m.address]);

  const vals = [
    m.displayName || '', 'zoho', connectionId, m.detectedType, choice.strategy,
    m.providerAccountId, m.providerGroupId, m.orgId, m.accessLevel || '',
    JSON.stringify(m.members || []), JSON.stringify(m.moderators || []),
    m.moderationCount || 0, JSON.stringify({ ...(caps || {}), confidence: choice.confidence }), choice.status, choice.detail,
  ];

  let id;
  if (existing) {
    // Strategy is switchable without data loss: messages stay keyed to mailbox id.
    await q(`UPDATE mailboxes SET display_name=$1, provider=$2, connection_id=$3, detected_type=$4, strategy=$5,
      provider_account_id=$6, provider_group_id=$7, org_id=$8, access_level=$9, members=$10, moderators=$11,
      moderation_count=$12, capabilities=$13, status=$14, status_detail=$15 WHERE id=$16`, [...vals, existing.id]);
    id = Number(existing.id);
  } else {
    const r = await one(`INSERT INTO mailboxes (address, display_name, provider, connection_id, detected_type,
      strategy, provider_account_id, provider_group_id, org_id, access_level, members, moderators,
      moderation_count, capabilities, status, status_detail)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`, [m.address, ...vals]);
    id = Number(r.id);
  }
  for (const alias of m.aliases || []) {
    if (alias === m.address) continue;
    await q(`INSERT INTO mailbox_aliases (address, mailbox_id) VALUES ($1,$2)
             ON CONFLICT (address) DO UPDATE SET mailbox_id = EXCLUDED.mailbox_id`, [alias, id]);
  }
  await q('INSERT INTO detection_reports (mailbox_id, report) VALUES ($1,$2)',
    [id, JSON.stringify({ discovery: m.evidence, capabilities: caps, choice })]);
  return id;
}

// ---- baseline comparison (validation only — never a data source) ----
function compareWithBaseline(discovered, baseline) {
  const discoveredSet = new Map(discovered.map(m => [lc(m.address), m]));
  const baselineSet = new Set((baseline || []).map(b => lc(b.address)));
  return {
    expectedCount: baselineSet.size,
    discoveredCount: discovered.length,
    matched: [...baselineSet].filter(a => discoveredSet.has(a)),
    missing: [...baselineSet].filter(a => !discoveredSet.has(a)),
    extra: [...discoveredSet.keys()].filter(a => !baselineSet.has(a)),
  };
}

module.exports = { discoverOrganization, probeCapabilities, chooseStrategy, upsertMailbox, compareWithBaseline, classifyGroup, sanitize };
