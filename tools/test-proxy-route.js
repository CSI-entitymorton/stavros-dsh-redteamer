// Unit self-check for the anonymized-egress plumbing (socks5.js + proxy-route.js):
// SOCKS5 handshake carries the target as a DOMAIN (remote DNS — no local leak), UA rotation stays
// inside the pool, scrubForwardHeaders drops identifying headers, and connectTunnel() rides the
// chained egress proxy (CONNECT -> SOCKS5 upstream) end-to-end. No external network.
// Run: node tools/test-proxy-route.js
const assert = require('assert');
const http = require('http'), net = require('net'), fs = require('fs'), os = require('os'), path = require('path');

const scopePath = path.join(os.tmpdir(), 'pr-scope-' + process.pid + '.json');
fs.writeFileSync(scopePath, JSON.stringify({ allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['127.0.0.1'], max_requests_per_second: 100 }));
process.env.SCOPE_JSON = scopePath;
process.env.EGRESS_AUDIT = path.join(os.tmpdir(), 'pr-audit-' + process.pid + '.jsonl');
const ROOT = path.join(__dirname, '..');

const { socks5Connect, buildTarget } = require('./socks5');
const { USER_AGENTS, rotateUA, scrubForwardHeaders, connectTunnel } = require('./proxy-route');
const { serve, STATE } = require('./egress-proxy');

// Watchdog: a silent hang must become a loud error, not a timeout in CI.
const step = { at: 'start' };
setTimeout(() => { console.error('proxy-route: HANG at step: ' + step.at); process.exit(2); }, 20000).unref();

// Wait for a server to be bound — poll address() as a fallback so a synchronous bind can never
// emit 'listening' before the once() handler is attached (which would hang the test).
function whenListening(server) {
  return new Promise((resolve) => {
    if (server.address()) return resolve();
    const t = setInterval(() => { if (server.address()) { clearInterval(t); resolve(); } }, 25);
    // Clear the poll on 'listening' too: if the server is closed before the next poll tick
    // (address() then returns null), the interval would otherwise leak and hang the test.
    server.once('listening', () => { clearInterval(t); resolve(); });
  });
}
// Minimal SOCKS5 upstream that records (host, port) and tunnels to it.
function startMockSocks() {
  const records = [];
  const server = net.createServer((c) => {
    let buf = Buffer.alloc(0); let stage = 'greet';
    c.on('error', () => {});
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 'greet' && buf.length >= 2) {
        if (buf.length < 2 + buf[1]) return;
        c.write(Buffer.from([0x05, 0x00]));
        buf = buf.slice(2 + buf[1]); stage = 'req';
      }
      if (stage === 'req' && buf.length >= 7) {
        const atyp = buf[3];
        let host, port, off;
        if (atyp === 0x03) { const l = buf[4]; if (buf.length < 5 + l + 2) return; host = buf.slice(5, 5 + l).toString('utf8'); port = buf.readUInt16BE(5 + l); off = 7 + l; }
        else if (atyp === 0x01) { host = [buf[4], buf[5], buf[6], buf[7]].join('.'); port = buf.readUInt16BE(8); off = 10; }
        else { c.destroy(); return; }
        records.push({ host, port });
        buf = buf.slice(off); stage = 'tunnel';
        const t = net.connect(port, host, () => {
          c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (port >> 8) & 0xff, port & 0xff]));
          t.pipe(c); c.pipe(t);
        });
        t.on('error', () => c.destroy()); c.on('error', () => t.destroy());
        c.on('close', () => t.destroy());
        t.on('close', () => c.destroy());
      }
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, records, port: server.address().port })));
}

(async () => {
  // --- buildTarget encodes a DOMAIN name (remote DNS), not a local resolution ---
  step.at = 'buildTarget';
  const b = buildTarget('api.target.com', 443);
  assert.strictEqual(b[0], 0x03, 'ATYP=domain');
  assert.strictEqual(b[1], 'api.target.com'.length);
  assert.strictEqual(b.slice(2, 2 + b[1]).toString(), 'api.target.com');
  assert.strictEqual(b.readUInt16BE(2 + b[1]), 443);

  // --- socks5Connect: handshake against the mock upstream, target recorded as domain ---
  const socks = await startMockSocks();
  step.at = 'origin+servers up';
  const origin = http.createServer((rq, rs) => rs.end('origin-ok')).listen(0, '127.0.0.1');
  await whenListening(origin);
  const originPort = origin.address().port;

  // 'localhost' is sent as a DOMAIN name -> the mock upstream resolves it (remote DNS), proving
  // the local resolver never sees the destination (DNS-leak guarantee).
  step.at = 'socks5Connect';
  const sock = await socks5Connect('127.0.0.1', socks.port, 'localhost', originPort);
  assert.ok(sock, 'socks5 socket connected');
  sock.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  const pong = await new Promise((r) => {
    let b = ''; const t = setTimeout(() => r(b), 2000);
    sock.on('data', (d) => { b += d; if (b.includes('origin-ok')) { clearTimeout(t); r(b); } });
  });
  assert.ok(pong.includes('origin-ok'), 'bytes tunneled through SOCKS5: ' + pong);
  assert.deepStrictEqual(socks.records, [{ host: 'localhost', port: originPort }], 'target sent as domain (remote DNS)');
  sock.destroy();

  // --- UA pool + rotation ---
  assert.ok(USER_AGENTS.length >= 5, 'UA pool has variety');
  for (const ua of USER_AGENTS) assert.ok(ua.startsWith('Mozilla/'), 'realistic UA: ' + ua.slice(0, 30));
  assert.ok(USER_AGENTS.includes(rotateUA(0)), 'seeded rotation inside pool');
  assert.notStrictEqual(rotateUA(0), rotateUA(1), 'rotation varies');

  // --- scrubForwardHeaders strips identifying/hop-by-hop headers ---
  const scrubbed = scrubForwardHeaders({
    'X-Forwarded-For': '10.0.0.5', 'Via': '1.1 proxy', 'Connection': 'keep-alive',
    'User-Agent': 'curl/8.0', 'Accept': '*/*', 'Host': 'x',
  });
  assert.strictEqual(scrubbed['X-Forwarded-For'], undefined);
  assert.strictEqual(scrubbed.Via, undefined);
  assert.strictEqual(scrubbed.Connection, undefined);
  assert.strictEqual(scrubbed['User-Agent'], 'curl/8.0');
  assert.strictEqual(scrubbed.Accept, '*/*');

  // --- connectTunnel: CONNECT through the CHAINED egress proxy reaches the origin ---
  step.at = 'connectTunnel';
  const chain = serve(0, { socks5: { host: '127.0.0.1', port: socks.port } });
  await whenListening(chain);
  const tunnel = await connectTunnel({ port: chain.address().port }, '127.0.0.1', originPort);
  tunnel.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n');
  const resp = await new Promise((r) => {
    let b = ''; const t = setTimeout(() => r(b), 2000);
    tunnel.on('data', (d) => { b += d; if (b.includes('origin-ok')) { clearTimeout(t); r(b); } });
  });
  assert.ok(resp.includes('200 OK') && resp.includes('origin-ok'), 'CONNECT tunnel carried HTTP through chain: ' + resp.slice(0, 60));
  tunnel.destroy();

  for (const srv of [origin, chain, socks.server]) {
    srv.closeAllConnections?.();
    srv.close();
  }
  fs.rmSync(scopePath, { force: true });
  fs.rmSync(STATE, { force: true }); // serve() writes daemon state; don't leave a dead-pid file behind
  console.log('proxy-route: all tests passed');
})();
