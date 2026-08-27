#!/usr/bin/env node
// Shared plumbing for the ANONYMIZED egress path.
//
// Two layers work together:
//   1. egress-proxy.js — the local scope-guarding forward proxy (127.0.0.1:9098). In
//      CHAINED mode it is given an upstream SOCKS5 anonymizer (Tor / VPN gateway /
//      commercial SOCKS5) and every forwarded request + CONNECT tunnel is carried over
//      that SOCKS5 socket. DNS is resolved AT the upstream (see socks5.js) so the local
//      resolver never sees the destination hostnames (no DNS leak).
//   2. proxy-route.js — what the harness' OWN Node tools (repeater.js, ...) use to ride
//      the same chain: load the running proxy state, build CONNECT+TLS tunnels for https,
//      absolute-form requests for http, and rotate realistic User-Agents.
//
// User-Agent rotation: in chained mode the proxy assigns a fresh browser UA per request
// so the exit fingerprint doesn't collapse to one tool string. scrubForwardHeaders()
// drops client-identifying headers (X-Forwarded-For etc.) before forwarding, so the
// upstream never sees our internal address.
const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const path = require('path');

const STATE = path.join(__dirname, '..', 'reports', 'tmp', 'egress-proxy.json');

// Read the running egress-proxy daemon state. Returns { port, socks5, started } or null.
function loadEgressProxy() {
  try {
    const s = JSON.parse(fs.readFileSync(STATE, 'utf8'));
    if (s && s.port) return { port: s.port, socks5: s.socks5 || null, started: s.started || null };
  } catch {}
  return null;
}

// Realistic modern desktop/mobile UA pool — rotate per request so egress looks like a
// normal browser mix, not one scanner string. Order is irrelevant; rotation is random.
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
];

// Random browser UA for one request. `seed` (optional) forces a deterministic index for tests.
function rotateUA(seed) {
  const i = seed != null ? seed % USER_AGENTS.length : Math.floor(Math.random() * USER_AGENTS.length);
  return USER_AGENTS[i];
}

// Headers that can reveal the client (internal IP / proxy hop). Stripped before forwarding
// to the upstream. Hop-by-hop headers are dropped too (Connection/Proxy-* stay local).
const STRIP_HEADERS = new Set([
  'x-forwarded-for', 'x-real-ip', 'client-ip', 'x-client-ip', 'x-forwarded', 'forwarded',
  'x-originating-ip', 'x-host', 'x-forwarded-host', 'x-forwarded-server', 'via',
  'proxy-authorization', 'proxy-connection', 'connection', 'keep-alive',
]);

// Returns a NEW headers object with identifying/hop-by-hop headers removed.
function scrubForwardHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (!STRIP_HEADERS.has(String(k).toLowerCase())) out[k] = v;
  }
  return out;
}

// HTTP CONNECT through the local egress proxy -> connected raw net.Socket to (host, port).
function connectTunnel(proxy, host, port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxy.port, '127.0.0.1');
    let buf = '';
    sock.on('connect', () => sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (!buf.includes('\r\n')) return;
      const line = buf.split('\r\n')[0];
      if (!/^HTTP\/1\.[01] 200/.test(line)) {
        sock.destroy();
        return reject(new Error('egress proxy CONNECT refused: ' + line));
      }
      const head = buf.split('\r\n\r\n')[0];
      const rest = buf.slice(head.length + 4);
      sock.removeAllListeners('data');
      if (rest.length) sock.unshift(Buffer.from(rest, 'latin1'));
      resolve(sock);
    });
    sock.on('error', (e) => reject(new Error('egress CONNECT error: ' + e.message)));
  });
}

// TLS socket to (host, port) inside a CONNECT tunnel through the local egress proxy.
// Resolves once the TLS handshake completes (secureConnect), so callers can hand it to
// http.request via createConnection() and write immediately.
function tlsTunnel(proxy, host, port) {
  return new Promise((resolve, reject) => {
    connectTunnel(proxy, host, port).then((raw) => {
      const t = tls.connect({ socket: raw, servername: host }, () => resolve(t));
      t.on('error', (e) => reject(new Error('egress TLS error: ' + e.message)));
    }).catch(reject);
  });
}

module.exports = {
  STATE, loadEgressProxy, USER_AGENTS, rotateUA, scrubForwardHeaders, connectTunnel, tlsTunnel,
};
if (require.main === module) {
  // `node tools/proxy-route.js check` — is the chain up and what does the outside see?
  const egress = loadEgressProxy();
  if (!egress) { console.error(JSON.stringify({ error: 'egress proxy is not running' })); process.exit(1); }
  const chain = egress.socks5 ? `${egress.socks5.host}:${egress.socks5.port}` : 'none (direct)';
  console.log(JSON.stringify({ proxy_port: egress.port, chain }, null, 2));
}
