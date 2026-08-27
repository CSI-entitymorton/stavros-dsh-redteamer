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
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const OOB_DIR = path.join(__dirname, '..', 'reports', 'oob');
const HITS = path.join(OOB_DIR, 'hits.jsonl');
const MARKERS = path.join(OOB_DIR, 'markers.jsonl');
const STATE = path.join(__dirname, '..', 'reports', 'tmp', 'oob.json');
const DEFAULT_PORT = 9099;

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
    const hits = marker ? all.filter((h) => (h.url || '').includes(marker)) : all;
    console.log(JSON.stringify({ total: all.length, marker: marker || null, matched: hits.length, hits: hits.slice(-tail) }, null, 2));
    return;
  }
  if (cmd === 'stop') return stop();
  if (cmd === 'status') {
    const s = state();
    const total = fs.existsSync(HITS) ? fs.readFileSync(HITS, 'utf8').split('\n').filter(Boolean).length : 0;
    console.log(JSON.stringify({ running: !!s, ...(s || {}), hit_count: total }));
    return;
  }
  console.error('usage: node tools/oob.js listen|marker|hits|stop|status [--port P] [--public-url U] [--tail N]');
  process.exit(2);
}

if (require.main === module) main();
module.exports = { logHit, recordMarker, DEFAULT_PORT, OOB_DIR, MARKERS };
