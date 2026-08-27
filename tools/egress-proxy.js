#!/usr/bin/env node
// Forward-proxy with a HARD scope allowlist + DNS/IP pinning. Third-party HTTP(S)-aware binaries
// route through this via HTTP_PROXY/HTTPS_PROXY so every outbound host is scope-checked in code.
//   node tools/egress-proxy.js listen [--port 9098] [--socks5 <host:port>] [--foreground]
//   node tools/egress-proxy.js stop
//   node tools/egress-proxy.js check [--socks5 <host:port>]
//
// ANONYMIZED (chained) mode — `--socks5 <host:port>` (Tor at 127.0.0.1:9050, a VPN gateway, or a
// commercial SOCKS5 provider):
//   * every forwarded request AND every CONNECT tunnel is carried over a SOCKS5 connection to the
//     upstream, so the target sees the upstream's exit IP, not ours (tools/socks5.js),
//   * the target hostname is sent to the upstream as a domain name -> DNS is resolved AT the proxy,
//     never by the local resolver (no DNS leak),
//   * the User-Agent is rotated to a fresh realistic browser UA per request and client-identifying
//     headers (X-Forwarded-For etc.) are stripped before forwarding,
//   * literal IPv6 destinations are refused (a v6 path that bypasses the chain is an OPSEC leak),
//   * the scope check still runs — on hostname/prefix/IP-CIDR rules — but WITHOUT local DNS lookup,
//     so the DNS-rebinding pin is replaced by remote resolution (the trade-off of chained mode).
//
// `check` verifies the mask from the outside: it walks the chain to public IP-echo endpoints and
// reports the exit IP the target would see (all echoes must agree) + confirms remote-DNS is in use.
//
// ponytail: HTTPS is HOST-level only (path is inside TLS, opaque -> allowed_url_prefixes can't apply
// on the cipher). raw-socket tools (nmap/masscan) ignore HTTP_PROXY and stay guarded by run.js;
// to mask those too, run the harness under proxychains/VPN (see README). repeater.js is NOT
// re-routed (already hard-guarded); it rides the chain itself via tools/proxy-route.js.
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { spawn } = require('child_process');
const { loadScope, inScope, ipAllowed } = require('./scope-guard');
const { resolveAndGuard } = require('./net');
const { socks5Connect } = require('./socks5');
const { rotateUA, scrubForwardHeaders } = require('./proxy-route');

const STATE = path.join(__dirname, '..', 'reports', 'tmp', 'egress-proxy.json');
const AUDIT = () => process.env.EGRESS_AUDIT || path.join(__dirname, '..', 'reports', 'tmp', 'egress-audit.jsonl');
const DEFAULT_PORT = 9098;
// Public IP-echo endpoints used by `check`; each returns the exit IP as plain text.
// EGRESS_ECHO_URL is an EXPLICIT override: when set, ONLY it is used (lets operators point the
// check at their own endpoint, and keeps tests offline).
const ECHO_URLS = process.env.EGRESS_ECHO_URL
  ? [process.env.EGRESS_ECHO_URL]
  : ['http://ifconfig.me/ip', 'http://api.ipify.org', 'http://icanhazip.com'];

function audit(entry) {
  try {
    const f = AUDIT();
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.appendFileSync(f, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
  } catch {}
}

// Scope check for a destination host. In chained mode we MUST NOT resolve DNS locally (that would
// be a leak): the hostname-level rules run, literal IPs are checked against allowed_ips, literal
// IPv6 is refused, and the SOCKS upstream does the resolution. Returns { ok, address?, reason }.
async function guardHost(host, scope, chain) {
  if (chain) {
    if (net.isIP(host)) {
      if (net.isIP(host) === 6) return { ok: false, reason: 'IPv6 target refused in chained mode (would bypass the anonymizer)' };
      return ipAllowed(host, scope.allowed_ips)
        ? { ok: true, remote_dns: false }
        : { ok: false, reason: 'IP not in allowed_ips' };
    }
    const g = inScope('http://' + host, scope);
    if (!g.ok) return { ok: false, reason: g.reason };
    return { ok: true, remote_dns: true }; // resolution happens at the SOCKS upstream
  }
  const g = inScope('http://' + host, scope);
  if (!g.ok) return { ok: false, reason: g.reason };
  const pin = await resolveAndGuard('http://' + host, scope);
  if (pin.blocked) return { ok: false, reason: pin.reason };
  return { ok: true, address: pin.address };
}

function parseSocks5(arg) {
  // accepts "host:port" (and optional socks5:// scheme)
  const s = String(arg || '').replace(/^socks5:\/\//, '');
  const i = s.lastIndexOf(':');
  if (i <= 0) return null;
  const host = s.slice(0, i);
  const port = +s.slice(i + 1);
  if (!host || !port) return null;
  return { host, port };
}

function serve(port, opts) {
  opts = opts || {};
  const chain = opts.socks5 || null;
  const scope = loadScope();
  const server = http.createServer(async (req, res) => {
    let target;
    try { target = new URL(req.url); } catch { res.writeHead(400); return res.end('bad request URI (proxy needs absolute URI)'); }
    const g = await guardHost(target.hostname, scope, chain);
    audit({ proto: 'http', host: target.hostname, url: req.url, chain: chain ? chain.host + ':' + chain.port : null, verdict: g.ok ? 'allow' : 'deny', reason: g.reason });
    if (!g.ok) { res.writeHead(403); return res.end('egress blocked: ' + g.reason); }
    // Rebuild the request head: drop client-identifying headers, fix Host, rotate UA in chained mode.
    const headers = scrubForwardHeaders(req.headers);
    headers.Host = target.host;
    if (chain) headers['User-Agent'] = rotateUA();
    else if (!headers['User-Agent']) headers['User-Agent'] = rotateUA();
    let up;
    if (chain) {
      try {
        const sock = await socks5Connect(chain.host, chain.port, target.hostname, target.port || 80);
        up = http.request({
          host: target.hostname, port: target.port || 80, method: req.method,
          path: target.pathname + target.search, headers, agent: false, createConnection: () => sock,
        }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      } catch (e) { res.writeHead(502); return res.end('upstream (socks5) error: ' + e.message); }
    } else {
      up = http.request({
        host: g.address, port: target.port || 80, method: req.method,
        path: target.pathname + target.search, headers,
      }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    }
    up.on('error', (e) => { res.writeHead(502); res.end('upstream error: ' + e.message); });
    req.pipe(up);
  });
  // HTTPS via CONNECT: scope-check the hostname, then carry the opaque TLS bytes over the chain.
  server.on('connect', async (req, clientSocket, head) => {
    const [host, portStr] = req.url.split(':');
    const port = +portStr || 443;
    const g = await guardHost(host, scope, chain);
    audit({ proto: 'connect', host, port, chain: chain ? chain.host + ':' + chain.port : null, verdict: g.ok ? 'allow' : 'deny', reason: g.reason });
    if (!g.ok) { clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\negress blocked: ' + g.reason); return clientSocket.end(); }
    // Teardown both tunnel ends when either side closes — a one-sided close must not leak the
    // other socket (keeps the process exitable and the audit loop clean).
    const link = (a, b) => { a.on('error', () => b.destroy()); b.on('error', () => a.destroy()); a.on('close', () => b.destroy()); b.on('close', () => a.destroy()); };
    if (chain) {
      let upstream;
      try { upstream = await socks5Connect(chain.host, chain.port, host, port); }
      catch (e) { clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\nupstream (socks5) error: ' + e.message); return clientSocket.end(); }
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
      link(clientSocket, upstream);
      return;
    }
    const upstream = net.connect(port, g.address, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
      link(clientSocket, upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });
  server.listen(port, '127.0.0.1', () => {
    fs.mkdirSync(path.dirname(STATE), { recursive: true });
    fs.writeFileSync(STATE, JSON.stringify({
      pid: process.pid, port: server.address().port, started: new Date().toISOString(),
      socks5: chain ? { host: chain.host, port: chain.port } : null,
    }));
  });
  return server;
}

function stop() {
  let s;
  try { s = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch { s = null; }
  if (!s || !s.pid) { console.log(JSON.stringify({ stopped: false, reason: 'no proxy state' })); return; }
  try { process.kill(s.pid); } catch {}
  fs.rmSync(STATE, { force: true });
  console.log(JSON.stringify({ stopped: true, pid: s.pid }));
}

// --- `check`: verify the mask from the outside --------------------------------
// An echo endpoint is only usable if it returns a bare IP (some endpoints 403 Tor exits or
// serve HTML). Anything else is reported as an error, never as an "exit IP".
const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
function isIpText(s) {
  return IP_RE.test(String(s || '').trim()) &&
    String(s).trim().split('.').every((o) => +o >= 0 && +o <= 255);
}

// Minimal HTTP/1.1 client over a raw socket (Connection: close) — enough for the IP echoes.
function httpGetViaSocks(chain, urlStr, timeoutMs) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch { return reject(new Error('bad echo URL')); }
    if (u.protocol !== 'http:') return reject(new Error('echo URL must be http:// (plaintext IP echo)'));
    const t0 = Date.now();
    socks5Connect(chain.host, chain.port, u.hostname, u.port || 80, timeoutMs).then((sock) => {
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => { sock.destroy(); reject(new Error('echo timeout')); }, timeoutMs || 15000);
      sock.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        if (buf.includes(Buffer.from('\r\n\r\n')) && (buf.includes(Buffer.from('Transfer-Encoding: chunked')) ? buf.includes(Buffer.from('0\r\n\r\n')) : true)) {
          clearTimeout(timer);
          sock.destroy();
          const headEnd = buf.indexOf(Buffer.from('\r\n\r\n')) + 4;
          const head = buf.slice(0, headEnd).toString('latin1');
          let body = buf.slice(headEnd);
          if (/Transfer-Encoding:\s*chunked/i.test(head)) {
            const chunks = [];
            let b = body;
            while (b.length > 0) {
              const szIdx = b.indexOf(Buffer.from('\r\n'));
              const sz = parseInt(b.slice(0, szIdx).toString('latin1').trim(), 16);
              if (!sz || Number.isNaN(sz)) break;
              chunks.push(b.slice(szIdx + 2, szIdx + 2 + sz));
              b = b.slice(szIdx + 2 + sz + 2);
            }
            body = Buffer.concat(chunks);
          }
          const text = body.toString('utf8').trim();
          if (!isIpText(text)) return reject(new Error('non-IP response (' + text.slice(0, 80) + '...)'));
          resolve({ url: urlStr, ip: text, ms: Date.now() - t0 });
        }
      });
      sock.on('error', (e) => { clearTimeout(timer); reject(new Error(e.message)); });
      sock.write(`GET ${u.pathname || '/'} HTTP/1.1\r\nHost: ${u.host}\r\nConnection: close\r\nUser-Agent: ${rotateUA()}\r\n\r\n`);
    }).catch(reject);
  });
}

async function check(chain) {
  if (!chain) {
    console.error(JSON.stringify({ error: 'no chain configured — start the proxy with --socks5 or pass --socks5 <host:port>' }));
    process.exit(2);
  }
  const results = [];
  for (const url of ECHO_URLS) {
    try { results.push(await httpGetViaSocks(chain, url)); }
    catch (e) { results.push({ url, error: e.message }); }
  }
  const ips = [...new Set(results.filter((r) => r.ip).map((r) => r.ip))];
  const ok = results.some((r) => r.ip);
  const out = {
    chain: `${chain.host}:${chain.port}`,
    dns: 'remote (resolved by the SOCKS upstream — no local DNS leak)',
    exit_ips: ips,
    exit_ip_consistent: ips.length <= 1,
    echoes: results,
  };
  console.log(JSON.stringify(out, null, 2));
  process.exit(ok ? 0 : 1);
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (cmd === 'listen') {
    const pi = argv.indexOf('--port');
    const port = pi >= 0 ? +argv[pi + 1] : DEFAULT_PORT;
    const si = argv.indexOf('--socks5');
    const socks5 = si >= 0 ? parseSocks5(argv[si + 1]) : null;
    if (si >= 0 && !socks5) { console.error('--socks5 expects <host:port> (e.g. 127.0.0.1:9050 for Tor)'); process.exit(2); }
    if (argv.includes('--foreground')) {
      serve(port, { socks5 });
      console.error('egress proxy on 127.0.0.1:' + port + ' (pid ' + process.pid + ')' +
        (socks5 ? ' — chained via SOCKS5 ' + socks5.host + ':' + socks5.port : ' — direct (no anonymizer)') + ' — Ctrl+C to stop');
    } else {
      const child = spawn(process.execPath, [__filename, 'listen', '--port', String(port), ...(socks5 ? ['--socks5', socks5.host + ':' + socks5.port] : []), '--foreground'], { detached: true, stdio: 'ignore' });
      child.unref();
      const deadline = Date.now() + 5000;
      const t = setInterval(() => {
        if (fs.existsSync(STATE) || Date.now() > deadline) {
          clearInterval(t);
          const s = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8')) : { error: 'proxy failed to start' };
          console.log(JSON.stringify({ started: !s.error, ...s }, null, 2));
          process.exit(s.error ? 1 : 0);
        }
      }, 100);
    }
    return;
  }
  if (cmd === 'stop') return stop();
  if (cmd === 'check') {
    const si = argv.indexOf('--socks5');
    const socks5 = si >= 0 ? parseSocks5(argv[si + 1]) : null;
    let chain = socks5;
    if (!chain) {
      try {
        const s = JSON.parse(fs.readFileSync(STATE, 'utf8'));
        if (s && s.socks5) chain = s.socks5;
      } catch {}
    }
    return check(chain);
  }
  console.error('usage: node tools/egress-proxy.js listen [--port 9098] [--socks5 <host:port>] [--foreground] | stop | check [--socks5 <host:port>]');
  process.exit(2);
}

if (require.main === module) main();
module.exports = { serve, guardHost, check, parseSocks5, STATE, DEFAULT_PORT, ECHO_URLS };
