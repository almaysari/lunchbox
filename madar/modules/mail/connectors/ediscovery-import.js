// eDiscovery / Admin Backup archive importer.
//
// This is the OFFICIAL Zoho path for the historical archive of shared
// mailboxes (Admin Console → eDiscovery → Backup/Exports → ZIP of EML files).
// It is an ARCHIVE IMPORT, not live sync — the UI must always label it so.
//
// Zero external deps: minimal ZIP reader (stored + deflate via zlib) and a
// minimal EML/MIME parser good enough for headers, text/html bodies and
// base64 attachments.
const zlib = require('zlib');

// ---------- ZIP ----------
function* zipEntries(buf) {
  // End Of Central Directory
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i > buf.length - 22 - 65536; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a ZIP file (EOCD not found)');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    // local header: skip its own name/extra lengths
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    const data = buf.subarray(dataStart, dataStart + compSize);
    yield {
      name,
      read: () => method === 8 ? zlib.inflateRawSync(data) : method === 0 ? Buffer.from(data) : null,
    };
    off += 46 + nameLen + extraLen + commentLen;
  }
}

// ---------- EML / MIME ----------
function decodeMimeWord(s) {
  return String(s || '').replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, cs, enc, text) => {
    try {
      if (enc.toUpperCase() === 'B') return Buffer.from(text, 'base64').toString('utf8');
      return Buffer.from(text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))), 'binary').toString('utf8');
    } catch { return text; }
  });
}

function parseHeaders(raw) {
  const headers = {};
  const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0) {
      const k = line.slice(0, i).trim().toLowerCase();
      if (!(k in headers)) headers[k] = decodeMimeWord(line.slice(i + 1).trim());
    }
  }
  return headers;
}

function decodeBody(body, encoding, isText) {
  const enc = String(encoding || '').toLowerCase();
  let buf;
  if (enc === 'base64') buf = Buffer.from(body.replace(/\s+/g, ''), 'base64');
  else if (enc === 'quoted-printable') {
    buf = Buffer.from(body.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))), 'binary');
  } else buf = Buffer.from(body, 'binary');
  return isText ? buf.toString('utf8') : buf;
}

function parseMime(raw) {
  const sep = raw.search(/\r?\n\r?\n/);
  const headRaw = sep >= 0 ? raw.slice(0, sep) : raw;
  const body = sep >= 0 ? raw.slice(sep).replace(/^\r?\n\r?\n/, '') : '';
  const headers = parseHeaders(headRaw);
  const ct = headers['content-type'] || 'text/plain';
  const result = { headers, text: null, html: null, attachments: [] };

  const boundaryMatch = ct.match(/boundary\s*=\s*"?([^";]+)"?/i);
  if (/^multipart\//i.test(ct) && boundaryMatch) {
    const parts = body.split(new RegExp('--' + boundaryMatch[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:--)?\r?\n?'));
    for (const part of parts) {
      if (!part.trim()) continue;
      const sub = parseMime(part);
      if (sub.html && !result.html) result.html = sub.html;
      if (sub.text && !result.text) result.text = sub.text;
      result.attachments.push(...sub.attachments);
    }
    return result;
  }

  const disp = headers['content-disposition'] || '';
  const nameMatch = (disp + ';' + ct).match(/(?:file)?name\s*=\s*"?([^";]+)"?/i);
  if (/attachment/i.test(disp) || (nameMatch && !/^text\//i.test(ct))) {
    result.attachments.push({
      name: decodeMimeWord(nameMatch ? nameMatch[1] : 'attachment.bin'),
      mime: ct.split(';')[0].trim(),
      data: decodeBody(body, headers['content-transfer-encoding'], false),
    });
  } else if (/text\/html/i.test(ct)) result.html = decodeBody(body, headers['content-transfer-encoding'], true);
  else if (/text\//i.test(ct)) result.text = decodeBody(body, headers['content-transfer-encoding'], true);
  return result;
}

// Parse one EML file into the platform's neutral message shape.
function parseEml(buf, sourceName = '') {
  const parsed = parseMime(buf.toString('binary'));
  const h = parsed.headers;
  const fromRaw = h['from'] || '';
  const fromEmail = (fromRaw.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/) || [''])[0];
  return {
    providerMessageId: h['message-id'] || ('eml:' + sourceName),
    rfcMessageId: h['message-id'] || '',
    threadId: h['references'] ? h['references'].split(/\s+/)[0] : '',
    from: fromEmail,
    fromName: fromRaw.replace(/<[^>]*>/, '').replace(/"/g, '').trim(),
    to: h['to'] || '',
    cc: h['cc'] || '',
    subject: h['subject'] || '',
    snippet: (parsed.text || parsed.html || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300),
    bodyHtml: parsed.html || (parsed.text ? '<pre>' + parsed.text.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])) + '</pre>' : null),
    receivedAt: h['date'] ? Date.parse(h['date']) || Date.now() : Date.now(),
    hasAttachments: parsed.attachments.length > 0,
    direction: 'in',
    attachments: parsed.attachments,
  };
}

// Iterate messages inside an eDiscovery/Backup export ZIP.
function* messagesFromExportZip(zipBuffer) {
  for (const entry of zipEntries(zipBuffer)) {
    if (!/\.eml$/i.test(entry.name)) continue;
    const data = entry.read();
    if (!data) continue;
    const msg = parseEml(data, entry.name);
    // Sent vs Inbox from the export's folder structure.
    if (/(^|\/)sent/i.test(entry.name)) msg.direction = 'out';
    msg.sourceFolder = entry.name.includes('/') ? entry.name.slice(0, entry.name.lastIndexOf('/')) : '';
    yield msg;
  }
}

module.exports = { messagesFromExportZip, parseEml, zipEntries };
