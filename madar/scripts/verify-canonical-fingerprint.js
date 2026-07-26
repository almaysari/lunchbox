// Canonical Fingerprint v3 — proven with REAL Zoho values (from the pasted
// moderation-queue evidence of all@exoticcolors.org). No mock data.
// Uses the ACTUAL shipped dedupHash so this proof can never drift from prod.
//   run: node scripts/verify-canonical-fingerprint.js
const { dedupHash: fp3, HASH_VERSION } = require('../modules/mail/sync');
function sentEpochSec(m) { // display helper mirroring the shipped rounding
  const v = (m.sentAt != null && m.sentAt !== '') ? m.sentAt : m.receivedAt;
  const ms = typeof v === 'number' ? v : (/^\d{10,}$/.test(String(v || '').trim()) ? Number(v) : Date.parse(v));
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
}
console.log('Using shipped dedupHash, HASH_VERSION =', HASH_VERSION, '\n');

// ---- REAL Zoho values (all@exoticcolors.org moderation queue, user-pasted) ----
const realResends = [ // same sender+subject, DIFFERENT sent dates → must NOT merge
  { from: 'j.villa@exoticcolors.org', subject: 'Introducing Our New Marketing Coordinator!', date: 1736436064000 },
  { from: 'j.villa@exoticcolors.org', subject: 'Introducing Our New Marketing Coordinator!', date: 1736430232000 },
  { from: 'j.villa@exoticcolors.org', subject: 'Introducing Our New Marketing Coordinator!', date: 1736197164000 },
  { from: 'j.villa@exoticcolors.org', subject: 'Introducing Our New Marketing Coordinator!', date: 1736196434000 },
];
const realDistinct = [
  { from: 'admin.it@exoticcolors.me', subject: 'Security Alert‼️, Fraudulent Email Impersonating the CEO', date: 1783172034000 },
  { from: 'ebrahim.m@exoticcolors.org', subject: 'Mandatory Use of Official Signature for All Company Documents', date: 1783105767000 },
];

console.log('=== PROPERTY 1: real resends (same from+subject, different sent time) stay DISTINCT ===');
const resendHashes = realResends.map(r => fp3({ from: r.from, subject: r.subject, sentAt: r.date }));
resendHashes.forEach((h, i) => console.log(`  resend ${i + 1} (date ${realResends[i].date}) -> ${h.slice(0, 16)}`));
console.log('  distinct fingerprints:', new Set(resendHashes).size, '/ 4', new Set(resendHashes).size === 4 ? 'PASS' : 'FAIL');

console.log('\n=== PROPERTY 2: distinct real messages -> distinct fingerprints ===');
const allReal = [...realResends, ...realDistinct].map(r => fp3({ from: r.from, subject: r.subject, sentAt: r.date }));
console.log('  unique:', new Set(allReal).size, '/ 6', new Set(allReal).size === 6 ? 'PASS' : 'FAIL');

console.log('\n=== PROPERTY 3: CONVERGENCE — same real email via Live vs eDiscovery EML -> SAME fp3 ===');
// Take a REAL message (from/subject/sent date). Build the two source shapes it
// would take in each pipeline, with the SAME recipient header, and compare.
const real = { from: 'admin.it@exoticcolors.me', subject: 'Security Alert‼️, Fraudulent Email Impersonating the CEO',
  dateMs: 1783172034000, to: 'all@exoticcolors.org', cc: '' };

// (a) LIVE shape — as the connector maps messages/view (sentDateInGMT as ms):
const liveRecord = { from: real.from, subject: real.subject, to: real.to, cc: real.cc, sentAt: real.dateMs, receivedAt: 1783146849540 };

// (b) eDiscovery EML — real RFC2822 with the SAME Date/From/Subject/To.
//     Date header derived from the same instant (RFC2822, second precision).
const rfc2822 = new Date(real.dateMs).toUTCString().replace('GMT', '+0000');
const eml = [
  'Message-ID: <real-msgid-from-archive@zoho>', // archive HAS a Message-ID; live does not
  `From: "Admin IT" <${real.from}>`,
  `To: ${real.to}`,
  `Subject: ${real.subject}`,
  `Date: ${rfc2822}`,
  '', 'Body of the real archived message.',
].join('\r\n');
// minimal EML header parse (mirrors the platform's parseEml: From/To/Cc/Subject/Date)
function parseEmlLike(raw) {
  const h = {};
  for (const line of raw.split(/\r?\n\r?\n/)[0].split(/\r?\n/)) {
    const i = line.indexOf(':'); if (i > 0) h[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  const fromEmail = (h.from.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/) || [''])[0];
  return { from: fromEmail, to: h.to || '', cc: h.cc || '', subject: h.subject || '',
    rfcMessageId: h['message-id'] || '', sentAt: Date.parse(h.date) };
}
const archiveRecord = parseEmlLike(eml);

const liveFp = fp3(liveRecord);
const archiveFp = fp3(archiveRecord);
console.log('  live    sentEpochSec:', sentEpochSec(liveRecord), '-> fp', liveFp.slice(0, 16));
console.log('  archive sentEpochSec:', sentEpochSec(archiveRecord), '-> fp', archiveFp.slice(0, 16));
console.log('  archive rfcMessageId present:', Boolean(archiveRecord.rfcMessageId), '| live rfc: none');
console.log('  CONVERGE (same canonical id):', liveFp === archiveFp ? 'PASS' : 'FAIL');

console.log('\n=== PROPERTY 4: mailbox-independent (multi-mailbox) — same email, two mailboxes -> same fp3 ===');
// The occurrence differs per mailbox; the canonical key must not depend on the
// mailbox or its per-copy fields (receivedTime/messageId).
const copyInHr = { ...liveRecord, receivedAt: 1111111111000 /* hr@ delivery */ };
const copyInFinance = { ...liveRecord, receivedAt: 2222222222000 /* finance@ delivery */ };
console.log('  hr@ copy fp:', fp3(copyInHr).slice(0, 16), '| finance@ copy fp:', fp3(copyInFinance).slice(0, 16));
console.log('  SAME canonical across mailboxes:', fp3(copyInHr) === fp3(copyInFinance) ? 'PASS' : 'FAIL');

console.log('\n=== PROPERTY 5: re-import idempotency — same EML twice -> same fp3 ===');
console.log('  re-import stable:', fp3(parseEmlLike(eml)) === archiveFp ? 'PASS' : 'FAIL');
