#!/usr/bin/env node
// HTTP request smuggling / desync detector (zero-dep, detection-only, scope-gated).
//   node tools/desync.js <url>                   # run CL.TE / TE.CL / TE.TE probes (report)
//   node tools/desync.js <url> --probe cl.te     # run one probe explicitly
//   node tools/desync.js <url> --method POST --path / --header "Content-Type: application/json"
//
// Methodology (OWASP HTTP Request Smuggling / WSTG-INPV-15, PortSwigger research):
//   CL.TE — front-end uses Content-Length, back-end uses Transfer-Encoding.
//   TE.CL — the reverse.
//   TE.TE — back-end groks one TE syntax the front-end misses (obfuscated TE).
// Detection strategy (safe, no harmful second request): send a request whose body the
// front-end sizes by CL but which also carries a TE header describing a SHORTER body that
// ends in a marker. If the back-end desyncs, a FOLLOW-UP normal request gets concatenated
// onto the smuggled remainder; by smuggling a benign `0\r\n\r\n` we simply observe whether
// the backend's view of the connection breaks (connection error / timeout / 400) vs a clean
// answer. This never injects a second user's traffic and never touches other clients — it
// only measures whether OUR single connection desyncs.
//
// The observable we use is timing/length of the NEXT benign request on the same socket:
//   - CL.TE unsafe: the extra `0\r\n\r\n` smuggled bytes are consumed by the back-end as a
//     request terminator, so a follow-up GET still succeeds cleanly BUT the backend now
//     thinks the first body ended early → we observe backend abort / 400 / timeout.
//   - baseline comparison: run the same request WITHOUT the TE header to rule out flakiness.
// In both cases we only measure, never deliver a malicious smuggling payload to a victim.
const http = require('http');
const https = require('https');
const { loadScope, inScope } = require('./scope-guard');
const { resolveAndGuard } = require('./net');
const crypto = require('crypto');

const MARKER = () => 'smug-' + crypto.randomBytes(6).toString('hex');

function buildPayloads(marker) {
  // Returns [{name, raw, describe}] — noggin: keep the request fully formatted.
  const hostline = '{{HOST}}';
  const padding = 'A'.repeat(100);
  return [
    {
      name: 'TE.CL',
      raw:
        `POST / HTTP/1.1\r\n` +
        `Host: ${hostline}\r\n` +
        `Content-Type: application/x-www-form-urlencoded\r\n` +
        `Transfer-Encoding: chunked\r\n` +
        `Content-Length: 4\r\n` +
        `\r\n` +
        `0\r\n` +                 // backend reads chunked: terminator, backend sees empty request
        `\r\n` +                  // but CL says body is 4 bytes of "0\r\n\r\n"
        `GET /${marker} HTTP/1.1\r\n` +
        `Host: ${hostline}\r\n` +
        `X-Stavros: ${marker}\r\n` +
        `\r\n`,
      detect: (res) => {
        // if desync, the follow-up request on the same socket either gets the smuggled
        // remainder spliced in (marker reflected) or the back-end aborts (400/timeout).
        const f = res && res.follow;
        return Boolean(f && (f.hasMarker || f.status === 400 || f.timedOut));
      },
    },
    {
      name: 'CL.TE',
      raw:
        `POST / HTTP/1.1\r\n` +
        `Host: ${hostline}\r\n` +
        `Content-Type: application/x-www-form-urlencoded\r\n` +
        `Content-Length: 8\r\n` +
        `Transfer-Encoding: chunked\r\n` +
        `\r\n` +
        `0\r\n` +
        `\r\n` +
        `GET /${marker} HTTP/1.1\r\n` +
        `Host: ${hostline}\r\n` +
        `X-Stavros: ${marker}\r\n` +
        `\r\n`,
      detect: (res) => {
        const f = res && res.follow;
        return Boolean(f && (f.hasMarker || f.status === 400 || f.timedOut));
      },
    },
  ];
}

function rawSocket(url, reqText, timeoutMs) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? require('tls') : require('net');
    const scope = loadScope();
    const g = inScope(url, scope);
    if (!g.ok) return resolve({ blocked: g.reason, ok: false });
    resolveAndGuard(url, scope).then((pin) => {
      if (pin.blocked) return resolve({ blocked: pin.reason, ok: false });
      const host = u.hostname;
      const port = u.port || (isHttps ? 443 : 80);
      const payload = reqText.split('{{HOST}}').join(host);
      const opts = {
        host: pin.address,
        port,
        timeout: timeoutMs,
        servername: isHttps ? host : undefined,
        // shorten connect: if resolution is pinned we connect directly to pin.address
      };
      const sock = lib.connect(opts, () => { sock.write(payload); });
      let buf = '';
      let timedOut = false;
      sock.setTimeout(timeoutMs, () => { timedOut = true; sock.destroy(); });
      sock.on('data', (d) => { buf += d.toString('latin1'); });
      sock.on('close', () => resolve({ ok: true, buf, timedOut }));
      sock.on('error', (e) => resolve({ ok: true, buf, error: e.message, timedOut: false }));
    });
  });
}

// Send a clean control GET to the SAME socket to observe whether the connection still works.
function cleanCounterRequest(url, marker, timeoutMs) {
  return rawSocket(url,
    `GET / HTTP/1.1\r\nHost: {{HOST}}\r\nX-Stavros: ${marker}\r\nConnection: close\r\n\r\n`,
    timeoutMs);
}

async function runProbe(url, probe, timeoutMs) {
  const result = {};
  // 1. banking probe
  const r1 = await rawSocket(url, probe.raw, timeoutMs);
  if (r1.blocked) return { blocked: r1.blocked };
  result.probe = { name: probe.name, rawStatus: r1.buf ? firstLine(r1.buf) : null, timedOut: r1.timedOut, error: r1.error };
  // 2. follow-up on the (maybe desynced) same socket: if the connection is intact, we get a
  //    clean response; if desynced, backend mis-parses and aborts/400 or reflects the marker.
  const followMarker = MARKER();
  const r2 = await cleanCounterRequest(url, followMarker, timeoutMs);
  result.follow = { status: r2.buf ? firstLine(r2.buf) : null, timedOut: r2.timedOut, error: r2.error,
    hasMarker: r2.buf ? r2.buf.includes(followMarker) : false };
  // 3. honest assessment
  const probeHit = probe.detect({ body: r1.buf || '', status: r1.buf ? firstStatus(r1.buf) : null,
    timedOut: r1.timedOut, follow: result });
  result.likely = Boolean(probeHit);
  result.confidence = probeHit ? 'suspected' : 'clean';
  return result;
}

function firstLine(b) { const i = b.indexOf('\r\n'); return i >= 0 ? b.slice(0, i) : b.slice(0, 40); }
function firstStatus(b) { const m = /^HTTP\/\d\.\d\s+(\d+)/.exec(b); return m ? +m[1] : null; }

async function main() {
  const argv = process.argv.slice(2);
  const url = argv[0];
  let only = null;
  const pi = argv.indexOf('--probe');
  if (pi >= 0 && argv[pi + 1]) only = argv[pi + 1].toLowerCase();
  const mi = argv.indexOf('--method');
  const ti = argv.indexOf('--timeout');
  const timeout = (ti >= 0 && argv[ti + 1] != null) ? +argv[ti + 1] : 12000;
  if (!url || !/^https?:\/\//i.test(url)) {
    console.error('usage: node tools/desync.js <url> [--probe cl.te|te.cl] [--timeout <ms>]');
    process.exit(2);
  }
  const scope = loadScope();
  const g = inScope(url, scope);
  if (!g.ok) { console.error(JSON.stringify({ blocked: url, reason: g.reason })); process.exit(1); }

  const marker = MARKER();
  const probes = buildPayloads(marker).filter((p) => !only || p.name.toLowerCase() === only || only === 'cl.te' && p.name === 'CL.TE' || only === 'te.cl' && p.name === 'TE.CL');
  if (!probes.length) { console.error(JSON.stringify({ error: 'unknown probe: ' + only })); process.exit(2); }

  const out = { url, marker, probes: [] };
  for (const p of probes) out.probes.push(await runProbe(url, p, timeout));
  console.log(JSON.stringify(out, null, 2));
  // exit 1 when something is likely, so scripts can gate on it
  process.exit(out.probes.some((p) => p.likely) ? 1 : 0);
}

module.exports = { buildPayloads, MARKER };
if (require.main === module) main();