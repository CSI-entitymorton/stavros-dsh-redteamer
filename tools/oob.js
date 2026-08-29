#!/usr/bin/env node
// Out-of-band (OOB) interaction listener — the missing piece for BLIND SSRF / blind XXE /
// blind RCE detection. Zero-dep HTTP server that logs every request it receives.
//
//   node tools/oob.js listen [--port 9099] [--public-url http://HOST:9099/] [--foreground]
//       Start the listener. By default it daemonizes (writes reports/tmp/oob.json with pid
//       + base URL) so the agent can keep working. Use --foreground to debug.
//       --public-url: the URL the TARGET can reach back to (LAN IP / port-forward).
//                     Default http://127.0.0.1:9099/ (lab/VPN targets only).
//   node tools/oob.js marker          -> print a fresh marker URL to inject (e.g. into an SSRF param)
//                                        and record it so hits can be attributed to that payload
//   node tools/oob.js hits [--tail N] [--marker <token>]
//                                      -> print recent interactions; --marker filters to one payload's hits
//   node tools/oob.js stop            -> stop the daemon
//   node tools/oob.js status          -> base URL, pid, hit count
//
// Workflow (blind SSRF): start listener -> inject marker URL into the URL-fetching param ->
// wait -> `oob.js hits` shows the target's fetch (source IP + request) = CONFIRMED blind SSRF.
// The listener itself is YOUR infrastructure — it is NOT scope-guarded (only targets are).
//
// Ondata 6 — DNS OOB channel (node:dgram, stdlib-only): many blind SSRF/XXE/RCE payloads only
// manifest as DNS lookups (no HTTP callback possible). A marker injected as <token>.oob.<domain>
// shows up as a query on this tiny authoritative-ish responder:
//   node tools/oob.js dns [--port 9053]     # UDP responder, foreground; every query is logged
//                                           # to hits.jsonl (kind:'dns'); marker queries are
//                                           # attributed via `hits --marker <token>`
// The responder answers A queries with 127.0.0.1 (TTL 1) — enough to elicit the follow-up
// connection in most payloads; malformed packets are ignored, never crash the listener.
const http = require('http');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const ssrfGuard = require('./ssrf-guard'); // B9 second layer (ondata 3)

// Ondata 3: env overrides (additive test/engagement hooks — defaults unchanged).
const OOB_DIR = process.env.OOB_DIR || path.join(__dirname, '..', 'reports', 'oob');
const HITS = path.join(OOB_DIR, 'hits.jsonl');
const MARKERS = path.join(OOB_DIR, 'markers.jsonl');
const STATE = process.env.OOB_STATE_FILE || path.join(__dirname, '..', 'reports', 'tmp', 'oob.json');
const DEFAULT_PORT = 9099;
const DEFAULT_DNS_PORT = 9053;

// B9 second layer: the public URL is what we hand to TARGETS as our callback base. A
// tampered/injected base pointing at cloud metadata or link-local would weaponize the
// target-side fetch — refuse it here. Loopback/RFC1918 bases are OUR OWN listener
// infrastructure (the default IS http://127.0.0.1:<port>/) and stay allowed;
// --allow-metadata-target lifts everything explicitly.
function guardPublicUrl(publicUrl, allowMetadata) {
  const v = ssrfGuard.checkTarget(publicUrl, { allowMetadata: !!allowMetadata, callbackBase: true });
  if (!v.ok) {
    console.error(JSON.stringify({ blocked: publicUrl, gate: 'ssrf-guard', tier: v.tier, range: v.range, reason: 'B9 ' + v.why }));
    process.exit(1);
  }
}

// Record every marker we hand out so `hits --marker <token>` can attribute a hit back to the
// exact payload that caused it (otherwise you can't tell WHICH SSRF/XXE param fired).
function recordMarker(token, base) {
  try {
    fs.mkdirSync(OOB_DIR, { recursive: true });
    fs.appendFileSync(MARKERS, JSON.stringify({ ts: new Date().toISOString(), token, url: base + token }) + '\n');
  } catch {}
}

function logHit(entry) {
  try {
    fs.mkdirSync(OOB_DIR, { recursive: true });
    fs.appendFileSync(HITS, JSON.stringify(entry) + '\n');
  } catch {}
}

// ─── Ondata 6: DNS OOB (stdlib dgram) ───────────────────────────────────────

// Marker tokens handed out so far (markers.jsonl) — used to attribute a DNS query to a payload.
function markerTokens() {
  try {
    return fs.readFileSync(MARKERS, 'utf8').split('\n').filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter((m) => m && typeof m.token === 'string')
      .map((m) => m.token);
  } catch { return []; }
}

// Parse a raw DNS query: 12-byte header + QNAME (labels, no compression allowed in question)
// + QTYPE/QCLASS. Returns {name, qtype, qclass, raw} or null on anything malformed.
function parseDnsQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 17) return null;
  const qdcount = buf.readUInt16BE(4);
  if (qdcount < 1) return null;
  let off = 12;
  const labels = [];
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) { off += 1; break; }
    if ((len & 0xc0) !== 0 || len > 63) return null; // compression pointer / oversized label
    if (off + 1 + len > buf.length) return null;
    labels.push(buf.toString('ascii', off + 1, off + 1 + len));
    off += 1 + len;
  }
  if (!labels.length || off + 4 > buf.length) return null;
  return {
    name: labels.join('.').toLowerCase(),
    qtype: buf.readUInt16BE(off),
    qclass: buf.readUInt16BE(off + 2),
    raw: buf,
  };
}

// Minimal response: echo id+question, QR=1|RD|RA, NOERROR; one A answer 127.0.0.1 (TTL 1)
// when QTYPE=A, else empty answer section. Enough to trigger the follow-up connection.
function dnsResponseFor(q) {
  const id = q.raw.slice(0, 2);
  const flags = Buffer.from([0x81, 0x80]); // QR=1, RD=1 (echoed), RA=1, RCODE=0
  const counts = Buffer.alloc(8);
  counts.writeUInt16BE(1, 0); // QDCOUNT
  counts.writeUInt16BE(q.qtype === 1 ? 1 : 0, 2); // ANCOUNT
  const qnameParts = [Buffer.from([0])];
  {
    const labels = q.name.split('.');
    const enc = [];
    for (const l of labels) {
      enc.push(Buffer.from([l.length]));
      enc.push(Buffer.from(l, 'ascii'));
    }
    enc.push(Buffer.from([0]));
    qnameParts[0] = Buffer.concat(enc);
  }
  const qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(q.qtype, 0);
  qtail.writeUInt16BE(q.qclass, 2);
  const question = Buffer.concat([qnameParts[0], qtail]);
  let answer = Buffer.alloc(0);
  if (q.qtype === 1) {
    const name = Buffer.from([0xc0, 0x0c]); // pointer to the question at offset 12
    const fixed = Buffer.alloc(10);
    fixed.writeUInt16BE(1, 0); // TYPE A
    fixed.writeUInt16BE(1, 2); // CLASS IN
    fixed.writeUInt32BE(1, 4); // TTL 1s
    fixed.writeUInt16BE(4, 8); // RDLENGTH
    answer = Buffer.concat([name, fixed, Buffer.from([127, 0, 0, 1])]);
  }
  return Buffer.concat([id, flags, counts, question, answer]);
}

// DNS OOB listener. Resolves once bound (tests bind port 0 for an ephemeral port). Malformed
// packets are dropped silently; post-bind socket errors never kill the listener.
function createDnsServer(port) {
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    const q = parseDnsQuery(msg);
    if (!q) return;
    const token = markerTokens().find((t) => q.name.includes(t)) || null;
    logHit({
      kind: 'dns', ts: new Date().toISOString(), qname: q.name, qtype: q.qtype,
      source_ip: rinfo.address, marker: token,
    });
    try { sock.send(dnsResponseFor(q), rinfo.port, rinfo.address); } catch { /* best-effort answer */ }
  });
  return new Promise((resolve, reject) => {
    const onErr = (e) => reject(e);
    sock.once('error', onErr);
    sock.bind(port, '0.0.0.0', () => {
      sock.removeListener('error', onErr);
      sock.on('error', () => {}); // post-bind: a datagram error must not kill the listener
      resolve(sock);
    });
  });
}

function createServer(port, publicUrl) {
  return http.createServer((req, res) => {
    const chunks = [];
    let len = 0;
    req.on('data', (d) => { len += d.length; if (chunks.length < 2) chunks.push(d); });
    req.on('end', () => {
      logHit({
        ts: new Date().toISOString(),
        method: req.method,
        url: req.url,
        source_ip: req.socket.remoteAddress || null,
        headers: { 'user-agent': req.headers['user-agent'] || null, 'content-type': req.headers['content-type'] || null, host: req.headers.host || null },
        body_bytes: len,
        body_preview: Buffer.concat(chunks).toString('utf8').slice(0, 512),
      });
      res.setHeader('content-type', 'text/plain');
      res.end('oob-hit-logged\n');
    });
    req.on('error', () => {});
  }).listen(port, '0.0.0.0', () => {
    fs.mkdirSync(path.dirname(STATE), { recursive: true });
    fs.writeFileSync(STATE, JSON.stringify({
      pid: process.pid,
      port,
      public_url: publicUrl,
      started: new Date().toISOString(),
    }));
  });
}

function daemonize(port, publicUrl) {
  const child = spawn(process.execPath, [__filename, 'listen', '--port', String(port), '--public-url', publicUrl, '--foreground'], {
    detached: true,
    stdio: 'ignore',
  });
  child.unref();
  // wait for the state file to appear (child writes it when listening)
  const deadline = Date.now() + 5000;
  const t = setInterval(() => {
    if (fs.existsSync(STATE) || Date.now() > deadline) {
      clearInterval(t);
      const s = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8')) : { error: 'listener failed to start' };
      console.log(JSON.stringify({ started: true, ...s }, null, 2));
      process.exit(s.error ? 1 : 0);
    }
  }, 100);
}

function state() {
  try {
    return JSON.parse(fs.readFileSync(STATE, 'utf8'));
  } catch {
    return null;
  }
}

function stop() {
  const s = state();
  if (!s || !s.pid) {
    console.log(JSON.stringify({ stopped: false, reason: 'no listener state (was it started?)' }));
    return;
  }
  try {
    process.kill(s.pid);
  } catch {}
  fs.rmSync(STATE, { force: true });
  console.log(JSON.stringify({ stopped: true, pid: s.pid }));
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const flag = (name) => { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] ? argv[i + 1] : null; };

  if (cmd === 'listen') {
    const port = +flag('port') || DEFAULT_PORT;
    const publicUrl = flag('public-url') || 'http://127.0.0.1:' + port + '/';
    guardPublicUrl(publicUrl, argv.includes('--allow-metadata-target'));
    if (argv.includes('--foreground')) {
      createServer(port, publicUrl);
      console.error('oob listener on ' + publicUrl + ' (pid ' + process.pid + ') — Ctrl+C to stop');
    } else {
      daemonize(port, publicUrl);
    }
    return;
  }
  if (cmd === 'marker') {
    const s = state();
    const base = s ? s.public_url : 'http://127.0.0.1:' + DEFAULT_PORT + '/';
    // B9: a state file tampered to a metadata/loopback base must not yield usable markers.
    guardPublicUrl(base, argv.includes('--allow-metadata-target'));
    const token = crypto.randomBytes(8).toString('hex');
    recordMarker(token, base);
    console.log(base + token);
    return;
  }
  if (cmd === 'hits') {
    const tail = +flag('tail') || 20;
    const marker = flag('marker');
    if (!fs.existsSync(HITS)) {
      console.log(JSON.stringify({ hits: [], marker: marker || null, note: 'no hits yet' }));
      return;
    }
    const lines = fs.readFileSync(HITS, 'utf8').split('\n').filter(Boolean);
    const all = lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const hits = marker ? all.filter((h) => ((h.url || '') + (h.qname || '')).includes(marker)) : all;
    console.log(JSON.stringify({ total: all.length, marker: marker || null, matched: hits.length, hits: hits.slice(-tail) }, null, 2));
    return;
  }
  if (cmd === 'dns') {
    const port = +flag('port') || DEFAULT_DNS_PORT;
    createDnsServer(port).then((sock) => {
      console.error(`oob DNS listener on 0.0.0.0:${sock.address().port} — hits → ${HITS} (foreground; Ctrl+C to stop)`);
    }).catch((e) => {
      console.error(JSON.stringify({ ok: false, error: `dns bind failed: ${e.message}` }));
      process.exit(1);
    });
    return;
  }
  if (cmd === 'stop') return stop();
  if (cmd === 'status') {
    const s = state();
    const total = fs.existsSync(HITS) ? fs.readFileSync(HITS, 'utf8').split('\n').filter(Boolean).length : 0;
    console.log(JSON.stringify({ running: !!s, ...(s || {}), hit_count: total }));
    return;
  }
  console.error('usage: node tools/oob.js listen|marker|hits|stop|status|dns [--port P] [--public-url U] [--tail N]\n' +
    '       [--allow-metadata-target]  (B9: lift metadata/loopback default-deny on --public-url)\n' +
    '       dns: UDP OOB responder (default port ' + DEFAULT_DNS_PORT + '), hits logged as kind:"dns"');
  process.exit(2);
}

if (require.main === module) main();
module.exports = { logHit, recordMarker, guardPublicUrl, DEFAULT_PORT, DEFAULT_DNS_PORT, OOB_DIR, MARKERS, markerTokens, parseDnsQuery, dnsResponseFor, createDnsServer };
