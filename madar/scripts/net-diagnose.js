#!/usr/bin/env node
// Network path diagnosis for the "HTTP 0" class of failures (docker skill:
// container networking / DNS / TLS / proxy are the usual culprits, and each has
// a DIFFERENT fix — so classify, don't guess).
//
// For each Zoho endpoint the connector actually uses, this tests the transport
// layers SEPARATELY and reports the first broken layer:
//   1. DNS      — resolve the hostname from inside this container
//   2. TCP      — open a socket to :443 (direct)
//   3. TLS      — complete a TLS handshake + certificate verification (direct)
//   4. HTTPS    — a real GET via Node fetch (honors HTTPS_PROXY/NO_PROXY env)
// If direct TCP/TLS fail but the fetch via proxy succeeds → egress requires the
// proxy (fix: make sure HTTPS_PROXY reaches the app container's environment).
// If DNS fails → container DNS (fix: docker daemon DNS / network policy).
// If TLS fails on verification → corporate TLS interception (fix: mount the CA
// bundle and set NODE_EXTRA_CA_CERTS).
//
// Read-only. Prints statuses and error codes only — no tokens, no payloads.
// Usage: docker compose exec app node scripts/net-diagnose.js [host ...]
const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

const DEFAULT_HOSTS = ['accounts.zoho.com', 'mail.zoho.com'];
const TIMEOUT = 8000;

const withTimeout = (p, ms, label) => Promise.race([p,
  new Promise((_, rej) => setTimeout(() => rej(new Error(label + ' timed out after ' + ms + 'ms')), ms).unref())]);

async function testDns(host) {
  try {
    const addrs = await withTimeout(dns.lookup(host, { all: true }), TIMEOUT, 'dns');
    return { ok: true, addresses: addrs.map(a => a.address) };
  } catch (e) { return { ok: false, code: e.code || null, error: String(e.message || e) }; }
}

function testTcp(host, port = 443) {
  return new Promise(resolve => {
    const s = net.connect({ host, port, timeout: TIMEOUT });
    s.on('connect', () => { s.destroy(); resolve({ ok: true }); });
    s.on('timeout', () => { s.destroy(); resolve({ ok: false, code: 'ETIMEDOUT', error: 'tcp connect timeout' }); });
    s.on('error', e => resolve({ ok: false, code: e.code || null, errno: e.errno, syscall: e.syscall, error: String(e.message) }));
  });
}

function testTls(host, port = 443) {
  return new Promise(resolve => {
    const s = tls.connect({ host, port, servername: host, timeout: TIMEOUT });
    s.on('secureConnect', () => {
      const cert = s.getPeerCertificate();
      resolve({ ok: true, authorized: s.authorized, protocol: s.getProtocol(),
        issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || null) : null,
        validTo: cert ? cert.valid_to : null });
      s.destroy();
    });
    s.on('timeout', () => { s.destroy(); resolve({ ok: false, code: 'ETIMEDOUT', error: 'tls handshake timeout' }); });
    s.on('error', e => resolve({ ok: false, code: e.code || null, error: String(e.message) }));
  });
}

async function testHttps(host) {
  try {
    const res = await fetch(`https://${host}/`, { method: 'GET', redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT) });
    return { ok: true, status: res.status, viaProxy: Boolean(process.env.HTTPS_PROXY || process.env.https_proxy) };
  } catch (e) {
    const root = e.cause || e;
    return { ok: false, name: e.name, code: root.code || null, syscall: root.syscall || null,
      error: String((root.message || e.message || e)).slice(0, 200) };
  }
}

function classify(r) {
  if (!r.dns.ok) return { layer: 'dns', fix: 'container DNS is broken for this host — check docker daemon DNS (/etc/docker/daemon.json), network policy, or /etc/resolv.conf in the container' };
  if (r.https.ok && (!r.tcp.ok || !r.tls.ok)) return { layer: 'proxy_required', fix: 'direct egress to :443 is blocked but the HTTP proxy works — ensure HTTPS_PROXY/NO_PROXY are set in the APP container env (compose env_file), not just on the host' };
  if (!r.tcp.ok) return { layer: 'tcp', fix: `outbound :443 blocked (${r.tcp.code || 'no route'}) — open egress to this host in the network policy/firewall` };
  if (!r.tls.ok) return { layer: 'tls', fix: `TLS handshake failed (${r.tls.code || 'unknown'}) — likely TLS interception; mount the corporate CA and set NODE_EXTRA_CA_CERTS` };
  if (r.tls.ok && r.tls.authorized === false) return { layer: 'tls_verify', fix: 'certificate not trusted — TLS interception; set NODE_EXTRA_CA_CERTS to the intercepting CA bundle' };
  if (!r.https.ok) return { layer: 'https', fix: `socket layers fine but HTTPS failed (${r.https.code || r.https.name}) — inspect proxy config (HTTPS_PROXY set but unreachable?) or server-side blocking` };
  return { layer: 'none', fix: 'all transport layers healthy — an HTTP 0 here would mean an app-level abort (timeout too low?) rather than network' };
}

async function main() {
  const hosts = process.argv.slice(2).filter(a => !a.startsWith('--'));
  const targets = hosts.length ? hosts : DEFAULT_HOSTS;
  const out = { at: new Date().toISOString(),
    proxyEnv: { HTTPS_PROXY: Boolean(process.env.HTTPS_PROXY || process.env.https_proxy),
      NO_PROXY: process.env.NO_PROXY || process.env.no_proxy || null,
      NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS || null },
    results: {} };
  for (const host of targets) {
    const r = { dns: await testDns(host) };
    r.tcp = r.dns.ok ? await testTcp(host) : { ok: false, skipped: 'dns failed' };
    r.tls = r.tcp.ok ? await testTls(host) : { ok: false, skipped: 'tcp failed' };
    r.https = await testHttps(host); // fetch does its own resolution/proxying — test it regardless
    r.classification = classify(r);
    out.results[host] = r;
    console.log(`\n${host}:`);
    console.log(`  dns   ${r.dns.ok ? 'OK ' + r.dns.addresses.join(',') : 'FAIL ' + (r.dns.code || r.dns.error)}`);
    console.log(`  tcp   ${r.tcp.ok ? 'OK' : 'FAIL ' + (r.tcp.code || r.tcp.skipped || r.tcp.error)}`);
    console.log(`  tls   ${r.tls.ok ? `OK ${r.tls.protocol} authorized=${r.tls.authorized}` : 'FAIL ' + (r.tls.code || r.tls.skipped || r.tls.error)}`);
    console.log(`  https ${r.https.ok ? `OK status=${r.https.status}${r.https.viaProxy ? ' (via proxy)' : ''}` : 'FAIL ' + (r.https.code || r.https.name)}`);
    console.log(`  => ${r.classification.layer.toUpperCase()}: ${r.classification.fix}`);
  }
  console.log('\nJSON evidence:\n' + JSON.stringify(out, null, 2));
}

main().catch(e => { console.error('net-diagnose failed:', e); process.exit(2); });
