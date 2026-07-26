// Group "mirrors" — deliver a mirrored copy of every shared group's mail into
// the collector by making the collector address a MEMBER of each Zoho group.
// Contracts (owner-mandated, same spirit as the collector's):
//
//   * plan is READ-ONLY and reads membership LIVE from Zoho — never the stored
//     member list (a stored list predating a membership change already hid a
//     collector once; see DECISIONS.md on the ai@ probe gap).
//   * writes go ONLY through the dedicated 'Madar Groups Admin' connection,
//     minted by collector-mirror.js grant with the groups scope alone and
//     approved by the owner in person — the discovery/admin read connection is
//     NEVER upgraded.
//   * add-only: this module can add the collector to a group, never remove or
//     modify anyone. Idempotent: an already-present member is skipped by plan.
//   * EXPLICIT ALLOWLIST ONLY: apply refuses to run without one — "all missing
//     groups" is never treated as approved. Policy-excluded groups
//     (EXCLUDED_FOR_NOW) are refused even when explicitly allowlisted.
//   * contained per group: one tenant rejection (4xx) is classified and
//     reported, the rest of the groups still apply. Every write is audited.
//   * honesty: membership is necessary but NOT sufficient for delivery —
//     group settings decide whether members get copies. The authoritative
//     proof stays the e2e capture probe (scripts/e2e-proof.js), and verdicts
//     say so instead of declaring success.
const { one, all } = require('../../core/db');
const { audit } = require('../../core/audit');

const GROUPS_ADMIN_LABEL = 'Madar Groups Admin';
const GROUPS_WRITE_SCOPE = 'ZohoMail.organization.groups.ALL';

// Owner-mandated policy exclusions: these groups are NEVER written to, even
// when explicitly allowlisted — apply refuses them and reports why. Lifting
// one is a code change (reviewed + tested), not a CLI flag.
const EXCLUDED_FOR_NOW = [
  'all@exoticcolors.ae',
  'all@exoticcolors.org',
  'ismail.yassin@exoticcolors.org',
  'notifications@exoticcolors.org',
  'system@exoticcolors.org',
  'officemailrestrictions@exoticcolors.org',
  'access@exoticcolors.org',
];

// Deterministic write-set resolution — pure, so the CLI can show the operator
// the EXACT set before confirmation and apply recomputes the same answer.
function resolveWriteSet(plan, allowlist) {
  const allow = [...new Set((allowlist || []).map(a => String(a).toLowerCase().trim()).filter(Boolean))];
  const excludedByPolicy = allow.filter(a => EXCLUDED_FOR_NOW.includes(a));
  const eligible = allow.filter(a => !EXCLUDED_FOR_NOW.includes(a));
  const byAddr = new Map(plan.groups.map(g => [String(g.address).toLowerCase(), g]));
  const unknownAddresses = eligible.filter(a => !byAddr.has(a));
  const writeSet = [], alreadyMirrored = [], unreadable = [];
  for (const a of eligible) {
    const g = byAddr.get(a);
    if (!g) continue;
    if (g.state === 'missing') writeSet.push(g);
    else if (g.state === 'already_mirrored') alreadyMirrored.push(a);
    else unreadable.push(a);
  }
  return { writeSet, excludedByPolicy, unknownAddresses, alreadyMirrored, unreadable };
}

function liveMembers(body) {
  const d = (body && body.data) || {};
  return (Array.isArray(d.mailGroupMemberList) ? d.mailGroupMemberList : [])
    .map(mm => String(mm.memberEmailId || '').toLowerCase()).filter(Boolean);
}

async function planMirror() {
  const addrs = require('./collector').collectorAddresses();
  if (!addrs.length) throw new Error('MADAR_COLLECTOR_ADDRESSES is not set — nothing to mirror into');
  const { ZohoClient } = require('./zoho-client');
  const rows = await all(`SELECT id, address, provider_group_id, org_id, connection_id FROM mailboxes
    WHERE detected_type='shared_mailbox' AND provider_group_id IS NOT NULL AND org_id IS NOT NULL
      AND NOT (lower(address) = ANY($1)) ORDER BY address`, [addrs]);
  const groups = [];
  for (const r of rows) {
    const base = { address: r.address, zgid: String(r.provider_group_id), orgId: String(r.org_id) };
    try {
      const zoho = await ZohoClient.cachedForConnection(Number(r.connection_id));
      const resp = await zoho.getGroupDetails(r.org_id, r.provider_group_id);
      if (resp.status !== 200) { groups.push({ ...base, state: 'unreadable', httpStatus: resp.status }); continue; }
      const members = liveMembers(resp.body);
      const present = addrs.find(a => members.includes(a)) || null;
      groups.push({ ...base, memberCount: members.length,
        state: present ? 'already_mirrored' : 'missing', collectorMember: present });
    } catch (e) {
      groups.push({ ...base, state: 'unreadable', error: e.message || 'unknown' });
    }
  }
  return { collector: addrs, groups };
}

async function applyMirror({ allowlist = null } = {}) {
  const allow = (Array.isArray(allowlist) ? allowlist : []).map(a => String(a).toLowerCase().trim()).filter(Boolean);
  if (!allow.length) {
    throw new Error('an explicit allowlist is required (--include a@x,b@y or --file <reviewed list>) — apply NEVER treats "all missing groups" as approved');
  }
  const plan = await planMirror();
  const collectorAddr = plan.collector[0];
  const resolved = resolveWriteSet(plan, allow);
  const conn = await one(`SELECT id FROM connections WHERE label=$1 AND status='connected'
    ORDER BY id DESC LIMIT 1`, [GROUPS_ADMIN_LABEL]);
  if (!conn) {
    throw new Error(`no connected "${GROUPS_ADMIN_LABEL}" connection — run collector-mirror.js grant and approve the consent first`);
  }
  const { ZohoClient } = require('./zoho-client');
  const zoho = await ZohoClient.cachedForConnection(Number(conn.id));
  const targets = resolved.writeSet;
  const applied = [];
  for (const g of targets) {
    let verdict, httpStatus = null, classification = null;
    try {
      const r = await zoho.addGroupMembers(g.orgId, g.zgid, [collectorAddr]);
      httpStatus = r.status; classification = r.classification || null;
      if (r.status === 200 || r.status === 201) {
        // live re-read is the membership proof — never trust the write's 200 alone
        const v = await zoho.getGroupDetails(g.orgId, g.zgid);
        verdict = (v.status === 200 && liveMembers(v.body).includes(collectorAddr))
          ? 'mirrored' : 'accepted_but_unverified';
      } else {
        verdict = 'rejected:http_' + r.status;
      }
    } catch (e) { verdict = 'error:' + (e.message || 'unknown'); }
    await audit(null, 'collector.mirror.add', g.address,
      JSON.stringify({ zgid: g.zgid, collector: collectorAddr, verdict, httpStatus, classification }));
    applied.push({ address: g.address, zgid: g.zgid, verdict, httpStatus, classification });
  }
  return {
    collector: collectorAddr, applied,
    excludedByPolicy: resolved.excludedByPolicy,
    unknownAddresses: resolved.unknownAddresses,
    alreadyMirrored: resolved.alreadyMirrored,
    unreadableAllowlisted: resolved.unreadable,
    note: 'membership is necessary but NOT sufficient for delivery — group settings decide member copies; the authoritative proof is the e2e capture probe (scripts/e2e-proof.js)',
  };
}

module.exports = { planMirror, applyMirror, resolveWriteSet,
  GROUPS_ADMIN_LABEL, GROUPS_WRITE_SCOPE, EXCLUDED_FOR_NOW };
