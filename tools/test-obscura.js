// Offline self-check for the Obscura wrapper (obscura.js) and the dom-check.js backend
// plumbing. No binary, no network: scope gates and argv assembly are pure; the CDP
// page-target logic runs against a localhost mock of /json/list + /json/new.
// Run: node tools/test-obscura.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

// Isolated state BEFORE the module loads (env is read per-call now, but keep it tidy).
const tmpDir = path.join(os.tmpdir(), 'obscura-test-' + process.pid);
fs.mkdirSync(tmpDir, { recursive: true });
process.env.OBSCURA_EGRESS_STATE = path.join(tmpDir, 'egress-proxy.json');
process.env.SCOPE_JSON = path.join(tmpDir, 'scope.json');

const ob = require('./obscura');
const { loadScope } = require('./scope-guard');

// ---- isolated scope + egress state (never touch the real ones) ----
const SCOPE = {
  allowed_hosts: ['target.com'],
  allowed_ips: ['127.0.0.1', '10.0.0.0/8'],
  max_requests_per_second: 2,
};
const scopeFile = path.join(tmpDir, 'scope.json');
fs.writeFileSync(scopeFile, JSON.stringify(SCOPE));
const egFile = path.join(tmpDir, 'egress-proxy.json');
fs.writeFileSync(egFile, JSON.stringify({ pid: 1, port: 9098, socks5: { host: '127.0.0.1', port: 9050 } }));
process.env.OBSCURA_EGRESS_STATE = egFile;

const scope = loadScope();

// ---- gate: in/out of scope ----
const g1 = ob.gateFor('fetch', ['https://app.target.com/a?b=c'], scope);
assert.strictEqual(g1.ok, true, 'subdomain of allowed host in scope');
assert.deepStrictEqual(g1.hosts, ['app.target.com'], 'host extracted');
assert.deepStrictEqual(g1.targets, ['https://app.target.com/a?b=c'], 'validated URL echoed back');
assert.strictEqual(ob.gateFor('fetch', ['http://127.0.0.1:3000/'], scope).ok, true, 'loopback via allowed_ips');
assert.deepStrictEqual(ob.gateFor('serve', [], scope).targets, [], 'serve has no targets');
const out = ob.gateFor('fetch', ['https://evil.com'], scope);
assert.strictEqual(out.ok, false, 'out-of-scope host refused');
assert.deepStrictEqual(out.bad, ['evil.com'], 'bad host reported');

// ---- gate: fail closed ----
assert.strictEqual(ob.gateFor('fetch', [], scope).ok, false, 'fetch with no URL refused');
assert.strictEqual(ob.gateFor('fetch', ['--dump', 'text'], scope).ok, false, 'flags alone are not targets');
assert.strictEqual(ob.gateFor('scrape', [], scope).ok, false, 'scrape with no URL refused');
assert.strictEqual(ob.gateFor('nuke', [], scope).ok, false, 'unknown command refused');
assert.strictEqual(
  ob.gateFor('fetch', ['https://a.target.com', 'https://b.target.com'], scope).ok, false,
  'fetch takes exactly one URL');

// ---- gate: one bad URL poisons the whole scrape batch ----
const mixed = ob.gateFor('scrape', ['http://10.1.2.3/x', 'https://nope.net/'], scope);
assert.strictEqual(mixed.ok, false, 'mixed scrape with out-of-scope host refused');
assert.ok(mixed.bad.includes('nope.net'), 'offending host listed');

// ---- parseArgs: boolean flags never eat positional URLs; values are not targets ----
const p1 = ob.parseArgs(['--stealth', 'https://a.target.com', '--dump', 'text']);
assert.strictEqual(p1.urls.length, 1, '--stealth keeps next token positional');
assert.strictEqual(p1.flags.get('stealth'), true, 'stealth is boolean');
assert.strictEqual(p1.flags.get('dump'), 'text', 'value flag captured');
const p2 = ob.parseArgs(['-s', '/tmp/p.png', '--eval', 'document.title']);
assert.strictEqual(p2.flags.get('screenshot'), '/tmp/p.png', '-s alias maps to screenshot');
assert.strictEqual(p2.flags.get('eval'), 'document.title', 'JS eval value captured verbatim');
const p3 = ob.parseArgs(['/tmp/report.html']);
assert.strictEqual(p3.urls.length, 1, 'parseArgs stays generic: positionals are kept');
assert.strictEqual(ob.gateFor('fetch', ['/tmp/report.html'], scope).ok, false,
  'a bare filename is not a valid target -> fail closed');
const g4 = ob.gateFor('scrape', ['https://a.target.com', '/tmp/junk.html'], scope);
assert.deepStrictEqual(g4.targets, ['https://a.target.com'], 'only validated URLs reach the child argv');

// ---- buildArgs: global flags precede the subcommand (v0.2.0 CLI grammar) ----
const b1 = ob.buildArgs('fetch', ['https://a.target.com'], { proxy: 'http://127.0.0.1:9098', dump: 'text', stealth: true });
assert.deepStrictEqual(b1.slice(0, 2), ['--proxy', 'http://127.0.0.1:9098'], 'proxy is global (before subcommand)');
assert.strictEqual(b1[2], 'fetch', 'subcommand follows globals');
assert.ok(b1.includes('--stealth'), 'stealth passed for fetch');
const b2 = ob.buildArgs('serve', [], { port: 9222, stealth: true });
assert.deepStrictEqual(b2,
  ['--proxy', 'http://127.0.0.1:9098', 'serve', '--port', '9222', '--stealth'],
  'serve argv shape: pinned to the running egress gateway');
const b3 = ob.buildArgs('scrape', ['u1', 'u2'], { stealth: true, concurrency: '99' });
assert.ok(b3.indexOf('--stealth') < b3.indexOf('scrape'), 'stealth is GLOBAL for scrape (before subcommand)');
assert.ok(b3.indexOf('--proxy') < b3.indexOf('scrape'), 'proxy is GLOBAL for scrape');
assert.ok(b3.includes('--concurrency'), 'concurrency passed');
// egress auto-pin: no explicit proxy -> gateway URL injected as global --proxy
const b4 = ob.buildArgs('fetch', ['https://a.target.com'], {});
assert.deepStrictEqual(b4.slice(0, 2), ['--proxy', 'http://127.0.0.1:9098'], 'egress gateway auto-pinned');
// explicit proxy wins over the gateway
const b5 = ob.buildArgs('scrape', ['https://a.target.com'], { proxy: 'socks5://1.2.3.4:1080' });
assert.deepStrictEqual(b5.slice(0, 2), ['--proxy', 'socks5://1.2.3.4:1080'], 'explicit --proxy wins');

// ---- concurrency clamp (pace.js cannot see obscura workers) ----
assert.strictEqual(ob.clampConcurrency('25'), ob.maxConcurrency(), 'clamped to OBSCURA_MAX_CONCURRENCY cap');
assert.strictEqual(ob.clampConcurrency('abc'), 2, 'garbage falls back to conservative default 2');
assert.strictEqual(ob.clampConcurrency(null), 2, 'missing defaults to 2');

// ---- effectiveProxy precedence ----
assert.strictEqual(ob.effectiveProxy({ proxy: 'x' }), 'x', 'explicit beats gateway');
assert.strictEqual(ob.effectiveProxy({}), 'http://127.0.0.1:9098', 'gateway when nothing explicit');

// ---- resolveBin honors STAVROS_OBSCURA_BIN ----
const fakeBin = path.join(tmpDir, 'fake-obscura');
fs.writeFileSync(fakeBin, '#!/bin/sh\n');
fs.chmodSync(fakeBin, 0o755);
process.env.STAVROS_OBSCURA_BIN = fakeBin;
assert.deepStrictEqual(ob.resolveBin(), { bin: fakeBin, source: 'env' }, 'env override resolves');
delete process.env.STAVROS_OBSCURA_BIN;

// ---- dom-check ensurePageTarget against a mock CDP HTTP endpoint ----
async function mockCdp(withExistingPage) {
  const created = { type: 'page', url: 'about:blank', webSocketDebuggerUrl: 'ws://127.0.0.1:0/devtools/page/mocked' };
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/json/list') {
      const body = withExistingPage ? [{ type: 'page', url: 'chrome://newtab', webSocketDebuggerUrl: 'ws://x' }, { type: 'iframe', url: 'about:blank' }] : [];
      res.end(JSON.stringify(body));
    } else if (req.url.startsWith('/json/new')) {
      // echo which method arrived so the test can assert PUT-first behavior
      res.end(JSON.stringify(Object.assign({ method: req.method }, created)));
    } else if (req.url === '/json/version') {
      res.end(JSON.stringify({ Browser: 'MockCDP/1.0' }));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

(async () => {
  const dc = require('./dom-check');

  // Case 1: a page target already exists (Chrome with an open tab) — no /json/new call.
  let s1 = await mockCdp(true);
  const port1 = s1.address().port;
  const r1 = await dc.ensurePageTarget(port1, 2000);
  assert.ok(r1.page && r1.page.url === 'chrome://newtab', 'existing page target reused');
  s1.close();

  // Case 2: empty target list (obscura serve starts tab-less) — a target is created.
  let s2 = await mockCdp(false);
  const port2 = s2.address().port;
  const r2 = await dc.ensurePageTarget(port2, 2000);
  assert.ok(r2.page && r2.page.webSocketDebuggerUrl, 'page target created when none exists');
  s2.close();

  // Case 3: waitForCdp reports null for a dead port (fast, bounded).
  const deadPort = await new Promise((r) => { const srv = require('net').createServer(); srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(() => r(p)); }); });
  const t0 = Date.now();
  const none = await dc.waitForCdp(deadPort, 1200);
  assert.strictEqual(none, null, 'dead CDP port yields null');
  assert.ok(Date.now() - t0 < 5000, 'wait is bounded');

  // cleanup + restore env
  delete process.env.SCOPE_JSON;
  delete process.env.OBSCURA_EGRESS_STATE;
  fs.rmSync(tmpDir, { recursive: true, force: true });

  console.log('obscura: all tests passed');
})().catch((e) => { console.error(e); process.exit(1); });
