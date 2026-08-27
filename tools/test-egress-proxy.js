// Offline self-check for the egress proxy (security path -> must have a test).
// Local origin in allowed_ips (127.0.0.1); in-scope forwarded, out-of-scope 403, audit records verdicts,
// run.js injects HTTP_PROXY when the daemon state file is present, AND the chained (--socks5) mode
// carries requests + CONNECT tunnels over a mock SOCKS5 upstream so the exit IP is the upstream's.
// Run: node tools/test-egress-proxy.js
const assert = require('assert');
const http = require('http'), net = require('net'), fs = require('fs'), os = require('os'), path = require('path');

const scopePath = path.join(os.tmpdir(), 'egr-scope-' + process.pid + '.json');
fs.writeFileSync(scopePath, JSON.stringify({ allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['127.0.0.1'], max_requests_per_second: 100 }));
const auditPath = path.join(os.tmpdir(), 'egr-audit-' + process.pid + '.jsonl');
process.env.SCOPE_JSON = scopePath;
process.env.EGRESS_AUDIT = auditPath;
const ROOT = path.join(__dirname, '..');
const { serve } = require('./egress-proxy');

// Watchdog: a silent hang must become a loud error, not a timeout in CI.
const step = { at: 'start' };
setTimeout(() => { console.error('egress-proxy: HANG at step: ' + step.at); process.exit(2); }, 30000).unref();

function proxyGet(proxyPort, absUrl) {
  return new Promise((resolve) => {
    const u = new URL(absUrl);
    const req = http.request({ host: '127.0.0.1', port: proxyPort, method: 'GET', path: absUrl, headers: { host: u.host }, agent: false },
      (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode, body: b })); });
    req.on('error', () => resolve({ status: 0 }));
    req.end();
  });
}
// Raw CONNECT: returns the proxy's first response line.
function connect(proxyPort, hostport) {
  return new Promise((resolve) => {
    const s = net.connect(proxyPort, '127.0.0.1', () => s.write(`CONNECT ${hostport} HTTP/1.1\r\nHost: ${hostport}\r\n\r\n`));
    let buf = '';
    s.on('data', (d) => { buf += d; if (buf.includes('\r\n')) { const line = buf.split('\r\n')[0]; s.destroy(); resolve(line); } });
    s.on('error', () => resolve('ERR'));
  });
}
// CONNECT + one HTTP GET over the tunnel; returns the full raw response text.
function connectAndGet(proxyPort, hostport, originHost) {
  return new Promise((resolve) => {
    const s = net.connect(proxyPort, '127.0.0.1', () => s.write(`CONNECT ${hostport} HTTP/1.1\r\nHost: ${hostport}\r\n\r\n`));
    let buf = '';
    let tunneled = false;
    s.on('data', (d) => {
      buf += d.toString('latin1');
      if (!tunneled && buf.includes('\r\n\r\n')) {
        const headEnd = buf.indexOf('\r\n\r\n') + 4;
        if (!/^HTTP\/1\.[01] 200/.test(buf)) { s.destroy(); return resolve(buf.split('\r\n')[0]); }
        tunneled = true;
        buf = buf.slice(headEnd);
        s.write(`GET /tunnel HTTP/1.1\r\nHost: ${originHost}\r\nConnection: close\r\n\r\n`);
      }
      if (tunneled && buf.includes('tunnel-ok')) { s.destroy(); resolve(buf); }
    });
    s.on('error', () => resolve('ERR'));
    setTimeout(() => { s.destroy(); resolve(buf || 'TIMEOUT'); }, 3000);
  });
}
// Minimal in-test SOCKS5 upstream (no-auth). Records every requested (host, port) — the DNS-leak
// assertion: the egress proxy must send DOMAIN names here, never resolve them locally.
function startMockSocks() {
  const records = [];
  const server = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    let stage = 'greet';
    c.on('error', () => {});
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 'greet' && buf.length >= 2) {
        const n = buf[1];
        if (buf.length < 2 + n) return;
        c.write(Buffer.from([0x05, 0x00])); // no-auth
        buf = buf.slice(2 + n);
        stage = 'req';
      }
      if (stage === 'req' && buf.length >= 7) {
        const atyp = buf[3];
        let host, port, off;
        if (atyp === 0x03) {
          const l = buf[4];
          if (buf.length < 5 + l + 2) return;
          host = buf.slice(5, 5 + l).toString('utf8'); port = buf.readUInt16BE(5 + l); off = 7 + l;
        } else if (atyp === 0x01) {
          host = [buf[4], buf[5], buf[6], buf[7]].join('.'); port = buf.readUInt16BE(8); off = 10;
        } else { c.destroy(); return; }
        records.push({ host, port });
        buf = buf.slice(off);
        stage = 'tunnel';
        const target = net.connect(port, host, () => {
          c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (port >> 8) & 0xff, port & 0xff]));
          target.pipe(c); c.pipe(target);
        });
        target.on('error', () => c.destroy());
        c.on('error', () => target.destroy());
        // Tear the tunnel down when either side closes — keeps the test process exitable.
        c.on('close', () => target.destroy());
        target.on('close', () => c.destroy());
      }
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, records, port: server.address().port })));
}
// Wait for a server to be bound. The bind can complete synchronously in some environments and
// emit 'listening' before a once() attached after listen() — poll address() as a fallback so a
// listen can never be missed and hang the test.
function whenListening(server) {
  return new Promise((resolve) => {
    if (server.address()) return resolve();
    const t = setInterval(() => { if (server.address()) { clearInterval(t); resolve(); } }, 25);
    // Clear the poll on 'listening' too: if the server is closed before the next poll tick
    // (address() then returns null), the interval would otherwise leak and hang the test.
    server.once('listening', () => { clearInterval(t); resolve(); });
  });
}
// Async spawn (parent event loop stays free so in-process servers respond).
function runNode(args, env) {
  return new Promise((resolve) => {
    const child = require('child_process').spawn(process.execPath, args, {
      cwd: ROOT, env: Object.assign({}, process.env, env || {}),
    });
    let out = '', err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

(async () => {
  let originHeaders = null;
  const origin = http.createServer((rq, rs) => {
    originHeaders = rq.headers;
    if (rq.url === '/hdr') return rs.end(JSON.stringify(rq.headers));
    if (rq.url === '/tunnel') return rs.end('tunnel-ok');
    rs.end('origin-ok');
  }).listen(0, '127.0.0.1');
  await whenListening(origin);
  const originPort = origin.address().port;

  // ---- direct (non-chained) mode: unchanged behavior ----
  const proxy = serve(0);
  await whenListening(proxy);
  const proxyPort = proxy.address().port;

  step.at = 'direct: serve up';
  const ok = await proxyGet(proxyPort, `http://127.0.0.1:${originPort}/x`);
  assert.strictEqual(ok.status, 200, 'in-scope forwarded');
  assert.strictEqual(ok.body, 'origin-ok');

  const bad = await proxyGet(proxyPort, 'http://10.9.9.9/x');
  assert.strictEqual(bad.status, 403, 'out-of-scope host blocked');

  const okConn = await connect(proxyPort, `127.0.0.1:${originPort}`);
  assert.ok(/200/.test(okConn), 'in-scope CONNECT tunneled: ' + okConn);
  const badConn = await connect(proxyPort, '8.8.8.8:443');
  assert.ok(/403/.test(badConn), 'out-of-scope CONNECT refused: ' + badConn);

  const audit = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  assert.ok(audit.some((a) => a.verdict === 'allow'), 'allow audited');
  assert.ok(audit.some((a) => a.verdict === 'deny'), 'deny audited');

  // run.js injects HTTP_PROXY for the spawned binary when the egress daemon state file is present.
  const { STATE } = require('./egress-proxy');
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify({ pid: process.pid, port: 9098 }));
  const { spawnSync } = require('child_process');
  const child = spawnSync(process.execPath,
    [path.join(ROOT, 'tools', 'run.js'), 'node', '-e', 'process.stdout.write(process.env.HTTP_PROXY||"none")', 'localhost'],
    { cwd: ROOT, env: Object.assign({}, process.env, { SCOPE_JSON: scopePath }), encoding: 'utf8' });
  assert.ok(child.stdout.includes('http://127.0.0.1:9098'), 'run.js passed HTTP_PROXY to child: ' + child.stdout);
  fs.rmSync(STATE, { force: true });

  // ---- chained (anonymized) mode ----
  step.at = 'chained: mock socks up';
  const socks = await startMockSocks();
  const chain = serve(0, { socks5: { host: '127.0.0.1', port: socks.port } });
  await whenListening(chain);
  const chainPort = chain.address().port;

  // HTTP forward rides the chain: origin sees a rotated browser UA, no X-Forwarded-For;
  // the SOCKS upstream received the request (host recorded) — that is the exit point.
  step.at = 'chained: http forward';
  const chained = await proxyGet(chainPort, `http://127.0.0.1:${originPort}/hdr`);
  assert.strictEqual(chained.status, 200, 'chained in-scope forwarded');
  const seenHeaders = JSON.parse(chained.body);
  assert.ok(/^Mozilla\/5\.0/.test(seenHeaders['user-agent']), 'rotated browser UA: ' + seenHeaders['user-agent']);
  assert.strictEqual(seenHeaders['x-forwarded-for'], undefined, 'no X-Forwarded-For leaked to origin');
  assert.ok(socks.records.some((r) => r.host === '127.0.0.1' && r.port === originPort), 'request reached the SOCKS upstream');

  // Out-of-scope still blocked in chained mode.
  const chainedBad = await proxyGet(chainPort, 'http://10.9.9.9/x');
  assert.strictEqual(chainedBad.status, 403, 'chained out-of-scope blocked');

  // Literal IPv6 destination refused in chained mode (a v6 path would bypass the anonymizer).
  const v6 = await proxyGet(chainPort, 'http://[::1]:80/x');
  assert.strictEqual(v6.status, 403, 'IPv6 refused in chained mode');

  // CONNECT through the chain: TLS bytes ride the SOCKS5 tunnel to the origin.
  step.at = 'chained: CONNECT tunnel';
  const chainedConn = await connectAndGet(chainPort, `127.0.0.1:${originPort}`, `127.0.0.1:${originPort}`);
  assert.ok(chainedConn.includes('tunnel-ok'), 'chained CONNECT tunnel delivered bytes: ' + chainedConn.slice(0, 80));

  // `check`: verify the exit IP the outside sees, through the chain.
  step.at = 'check(ip): create echo servers';
  const echo = http.createServer((rq, rs) => rs.end('203.0.113.7')).listen(0, '127.0.0.1');
  const htmlEcho = http.createServer((rq, rs) => rs.end('<html><body>403 Forbidden</body></html>')).listen(0, '127.0.0.1');
  await whenListening(echo);
  await whenListening(htmlEcho);
  step.at = 'check(ip): spawning subprocess';
  const checkRes = await runNode(
    [path.join(ROOT, 'tools', 'egress-proxy.js'), 'check', '--socks5', `127.0.0.1:${socks.port}`],
    { EGRESS_ECHO_URL: `http://127.0.0.1:${echo.address().port}/ip` }
  );
  step.at = 'check(ip) subprocess';
  const chk = JSON.parse(checkRes.out);
  assert.strictEqual(checkRes.code, 0, 'check exit 0: ' + checkRes.err);
  assert.deepStrictEqual(chk.exit_ips, ['203.0.113.7'], 'exit IP is the upstream view: ' + checkRes.out);
  assert.strictEqual(chk.exit_ip_consistent, true);
  assert.ok(/remote/.test(chk.dns), 'remote DNS confirmed: ' + chk.dns);

  // An echo that answers HTML (some endpoints 403 Tor exits) must NOT be reported as an IP.
  const htmlCheck = await runNode(
    [path.join(ROOT, 'tools', 'egress-proxy.js'), 'check', '--socks5', `127.0.0.1:${socks.port}`],
    { EGRESS_ECHO_URL: `http://127.0.0.1:${htmlEcho.address().port}/ip` }
  );
  step.at = 'check(html) subprocess';
  const hchk = JSON.parse(htmlCheck.out);
  assert.strictEqual(htmlCheck.code, 1, 'non-IP echo -> check exit 1');
  assert.deepStrictEqual(hchk.exit_ips, [], 'HTML response is not an exit IP');
  assert.ok(/non-IP response/.test(hchk.echoes[0].error), 'error explains why: ' + hchk.echoes[0].error);

  step.at = 'repeater subprocess';
  // repeater.js rides the chain too (state file written by the chained serve).
  const repeater = await runNode(
    [path.join(ROOT, 'tools', 'repeater.js'), '--url', `http://127.0.0.1:${originPort}/hdr`, '--show-body'],
    { SCOPE_JSON: scopePath }
  );
  assert.strictEqual(repeater.code, 0, 'repeater through chain exit 0: ' + repeater.err);
  assert.ok(repeater.out.includes('"status": 200'), 'repeater got 200 through the chain: ' + repeater.out.slice(0, 200));
  // The last request the origin saw was the repeater's — its headers prove the chain's hygiene.
  step.at = 'assert repeater headers';
  assert.ok(/^Mozilla\/5\.0/.test(originHeaders['user-agent']), 'repeater request got rotated browser UA');
  assert.strictEqual(originHeaders['x-forwarded-for'], undefined, 'repeater request did not leak X-Forwarded-For');

  fs.rmSync(STATE, { force: true });
  for (const srv of [origin, proxy, chain, socks.server, echo, htmlEcho]) {
    srv.closeAllConnections?.();
    srv.close();
  }
  fs.rmSync(scopePath, { force: true }); fs.rmSync(auditPath, { force: true });
  console.log('egress-proxy: all tests passed');
})();
