// End-to-end test for the repeater engine upgrades: --vary/--diff, --follow + cookie jar,
// --extract/--var, --upload, --race, --timeout. Uses a local mock server + a temp scope.json
// (via the SCOPE_JSON env override). No external network.
// Run: node tools/test-repeater-e2e.js
const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stavros-e2e-'));
const scopePath = path.join(tmpDir, 'scope.json');
fs.writeFileSync(scopePath, JSON.stringify({
  allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['127.0.0.1'], max_requests_per_second: 100,
}));

let raceCounter = 0;
let lastEchoBody = null;
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  if (u.pathname === '/vary') {
    const x = u.searchParams.get('x');
    res.setHeader('content-type', 'text/plain');
    return res.end('alpha beta gamma ' + (x === '1' ? 'delta' : 'omega'));
  }
  if (u.pathname === '/redirect') {
    res.setHeader('set-cookie', 'sid=abc123; Path=/; HttpOnly');
    res.statusCode = 302;
    res.setHeader('location', '/final');
    return res.end();
  }
  if (u.pathname === '/final') {
    const cookie = req.headers.cookie || '';
    return res.end(cookie.includes('sid=abc123') ? 'cookie-ok' : 'cookie-missing');
  }
  if (u.pathname === '/extract') {
    return res.end('prefix token=XYZ12345 suffix');
  }
  if (u.pathname === '/upload') {
    const body = [];
    req.on('data', (d) => body.push(d));
    req.on('end', () => {
      const text = Buffer.concat(body).toString('latin1');
      const okFile = text.includes('filename="evil.html"');
      const okField = text.includes('name="note"') && text.includes('hello-note');
      return res.end('upload-ok:' + (okFile && okField ? 'both' : 'missing:' + (okFile ? 'field' : 'file')));
    });
    return;
  }
  if (u.pathname === '/race') {
    raceCounter++;
    return res.end('race#' + raceCounter);
  }
  if (u.pathname === '/echo') {
    const body = [];
    req.on('data', (d) => body.push(d));
    req.on('end', () => {
      lastEchoBody = Buffer.concat(body).toString('utf8');
      res.end('echo-ok');
    });
    return;
  }
  if (u.pathname === '/hang') {
    return; // never respond -> client timeout
  }
  res.statusCode = 404;
  res.end('nope');
});

// Spawn asynchronously: the parent's event loop must stay free so the in-process mock server
// can respond (spawnSync would deadlock it).
function runRepeater(args, extraEnv) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(ROOT, 'tools', 'repeater.js'), ...args], {
      cwd: ROOT,
      env: Object.assign({}, process.env, { SCOPE_JSON: scopePath }, extraEnv || {}),
    });
    let out = '', err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => {
      if (code !== 0) return reject(new Error('repeater exited ' + code + ': ' + err));
      try {
        resolve(JSON.parse(out));
      } catch (e) {
        reject(new Error('bad repeater JSON output: ' + out));
      }
    });
  });
}

function runRepeaterSyncExpectFail(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(ROOT, 'tools', 'repeater.js'), ...args], {
      cwd: ROOT,
      env: Object.assign({}, process.env, { SCOPE_JSON: scopePath }),
    });
    let out = '', err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => resolve({ code, out: out + err }));
  });
}

async function main() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  // 1) --vary + --diff: body similarity catches same-length different-content
  const vary = await runRepeater(['--url', `${base}/vary?x=FUZZ`, '--vary', 'x=1,2', '--diff']);
  assert.strictEqual(vary.length, 2);
  assert.strictEqual(vary[0].status, 200);
  assert.strictEqual(vary[1].status, 200);
  assert.ok(vary[1].body_similarity > 0.5 && vary[1].body_similarity < 1,
    'similar but distinct bodies -> similarity in (0.5,1), got ' + vary[1].body_similarity);
  assert.strictEqual(vary[0].body_similarity, undefined, 'baseline has no similarity');

  // 2) --follow + cookie jar via --session
  const sess = path.join(tmpDir, 's.json');
  const [follow1] = await runRepeater(['--url', `${base}/redirect`, '--follow', '--session', sess, '--show-body']);
  assert.strictEqual(follow1.status, 200, 'follow1 status');
  assert.strictEqual(follow1.body, 'cookie-ok');
  assert.ok(follow1.hop > 0, 'redirect followed');
  // cookie persisted: a fresh process WITHOUT --follow still sends the stored cookie
  const [follow2] = await runRepeater(['--url', `${base}/final`, '--session', sess, '--show-body']);
  assert.strictEqual(follow2.body, 'cookie-ok', 'cookie jar persisted across processes');

  // 3) --extract + {{var}} substitution
  const sess2 = path.join(tmpDir, 's2.json');
  const [ex] = await runRepeater(['--url', `${base}/extract`, '--extract', 'tok=token=([A-Z0-9]+)', '--session', sess2, '--show-body']);
  assert.strictEqual(ex.extracted.tok, 'XYZ12345');
  const [sub] = await runRepeater(['--url', `${base}/extract?echo={{tok}}`, '--session', sess2]);
  assert.strictEqual(sub.status, 200, '{{tok}} substituted without error, got ' + JSON.stringify(sub));

  // 4) --upload multipart
  const upFile = path.join(tmpDir, 'evil.html');
  fs.writeFileSync(upFile, '<script>alert(1)</script>');
  const [up] = await runRepeater(['--url', `${base}/upload`, '--method', 'POST', '--upload', 'file=' + upFile,
    '--form', 'note=hello-note', '--show-body']);
  assert.strictEqual(up.body, 'upload-ok:both');

  // 5) --race N concurrent volley
  const rc = await runRepeater(['--url', `${base}/race`, '--race', '5']);
  assert.strictEqual(rc.length, 1);
  assert.strictEqual(rc[0].volley.length, 5);
  assert.ok(rc[0].volley.every((v) => v.status === 200));

  // 6) --timeout on a hanging endpoint
  const [hang] = await runRepeater(['--url', `${base}/hang`, '--timeout', '1200']);
  assert.strictEqual(hang.timeout, true, 'hanging endpoint reports timeout');

  // 7) hard scope guard still blocks out-of-scope targets
  const blocked = await runRepeaterSyncExpectFail(['--url', 'https://evil.com/x']);
  assert.strictEqual(blocked.code, 1, 'out-of-scope target exits 1');
  assert.ok(blocked.out.includes('blocked'), 'blocked message printed');

  // 8) STAVROS_PRIVACY=1: the --data body must be rehydrated to the REAL value before it
  // ever hits the wire, not sent as a raw placeholder. Env is scoped to this one spawn only.
  // Asserted server-side (lastEchoBody) since the tokenize()-wrapped stdout would re-mask
  // the real value on the way out and give a false pass either way.
  const tokenMapPath = path.join(tmpDir, 'token-map.json');
  const REAL = 'EXAMPLE_live_key_1234567890abcdef';
  const TOKEN = 'SECRET_001';
  fs.writeFileSync(tokenMapPath, JSON.stringify({ forward: { [REAL]: TOKEN }, counters: { SECRET: 1 } }));
  const [echoed] = await runRepeater(
    ['--url', `${base}/echo`, '--method', 'POST', '--data', JSON.stringify({ x: TOKEN })],
    { STAVROS_PRIVACY: '1', TOKEN_MAP: tokenMapPath }
  );
  assert.strictEqual(echoed.status, 200, 'echo request succeeded');
  assert.ok(lastEchoBody.includes(REAL), 'wire body rehydrated to the real secret before send, got ' + lastEchoBody);
  assert.ok(!lastEchoBody.includes(TOKEN), 'placeholder must never reach the real target, got ' + lastEchoBody);

  server.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log('repeater-e2e: all tests passed');
}

main().catch((e) => {
  console.error('FAILED:', e.message);
  process.exit(1);
});
