#!/usr/bin/env node
// test-benchgen.js — self-tests for tools/gen-bench.js (contamination-proof benchmark).
// Verifies: generation, determinism, anti-cheat (seed variance), boot, route leak,
// every vulnerability class actually triggers, and eval scoring both ways.
'use strict';

const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const TOOLS = __dirname;
const { findingBlob, matchesBenchPort } = require(path.join(TOOLS, 'gen-bench.js'));
const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'benchgen-'));
let failures = 0;

function check(name, cond, detail) {
  if (cond) console.log('PASS  ' + name);
  else { failures++; console.log('FAIL  ' + name + (detail ? ' — ' + detail : '')); }
}

function freePort() {
  return new Promise((resolve) => {
    const srv = http.createServer();
    srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(() => resolve(p)); });
  });
}

function httpReq(port, method, pathname, opts = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: pathname, headers: opts.headers }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    });
    req.on('error', e => resolve({ error: e.message }));
    if (opts.body != null) req.write(opts.body);
    req.end();
  });
}

const b64url = s => Buffer.from(s).toString('base64').replace(/=+$/g, '');

async function waitUp(port, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try { const r = await httpReq(port, 'GET', '/'); if (r.status) return true; } catch (e) {}
    await new Promise(r => setTimeout(r, 100));
  }
  return false;
}

function genBench(seed, port, out) {
  return JSON.parse(execFileSync(process.execPath,
    [path.join(TOOLS, 'gen-bench.js'), 'new', '--seed', String(seed), '--port', String(port), '--out', out, '--json'],
    { encoding: 'utf8' }));
}

async function main() {
  const port = await freePort();
  const outDir = path.join(tmpBase, 'bench-main-' + port);

  // ── generation ──
  console.log('generating bench (seed 424242, port ' + port + ')...');
  const meta = genBench(424242, port, outDir);
  check('generator emits app.js + manifest.full.json',
    fs.existsSync(path.join(outDir, 'app.js')) && fs.existsSync(path.join(outDir, 'manifest.full.json')));
  const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.full.json'), 'utf8'));
  check('manifest has all 15 classes', manifest.classes.length === 15, 'got ' + manifest.classes.length);
  check('routes unique', new Set(manifest.classes.map(c => c.route)).size === manifest.classes.length);
  check('black-box: manifest not inside workspace', outDir.startsWith(tmpBase));

  // ── determinism + anti-cheat ──
  const outDir2 = path.join(tmpBase, 'bench-same-' + port);
  const m2 = JSON.parse(fs.readFileSync(path.join(genBench(424242, port + 1, outDir2).dir, 'manifest.full.json'), 'utf8'));
  check('same seed → identical routes (deterministic)',
    JSON.stringify(manifest.classes.map(c => c.route)) === JSON.stringify(m2.classes.map(c => c.route)));
  const outDir3 = path.join(tmpBase, 'bench-diff-' + port);
  const m3 = JSON.parse(fs.readFileSync(path.join(genBench(999999, port + 2, outDir3).dir, 'manifest.full.json'), 'utf8'));
  check('different seed → different routes (anti-cheat)',
    JSON.stringify(manifest.classes.map(c => c.route)) !== JSON.stringify(m3.classes.map(c => c.route)));

  // ── boot + smoke ──
  const child = spawn(process.execPath, ['app.js'], { cwd: outDir, stdio: ['ignore', 'pipe', 'pipe'] });
  check('app boots and listens', await waitUp(port), 'port ' + port);
  const mainjs = await httpReq(port, 'GET', '/static/main.js');
  check('main.js leaks route registry (JS route-analysis surface)',
    mainjs.status === 200 && mainjs.body.includes('window.__API__'));

  // ── per-class trigger tests ──
  for (const c of manifest.classes) {
    const t = c.test;
    if (!t) {
      if (c.id === 'jwt') {
        const hdr = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
        const pl = b64url(JSON.stringify({ username: 'admin', role: 'admin' }));
        const r = await httpReq(port, 'GET', c.route + '/me', { headers: { Authorization: 'Bearer ' + hdr + '.' + pl + '.' } });
        check('trigger jwt (alg:none → admin)', r.status === 200 && r.body.includes('"role":"admin"'),
          'status=' + r.status + ' body=' + r.body.slice(0, 120));
      } else if (c.id === 'pp') {
        const p = await httpReq(port, 'POST', c.route, { headers: { 'Content-Type': 'application/json' }, body: '{"__proto__":{"polluted":true}}' });
        const g = await httpReq(port, 'GET', c.route + '/check');
        check('trigger pp (pollution confirmed)', p.status === 200 && g.status === 200 && g.body.includes('"polluted":true'),
          'post=' + p.status + ' check=' + g.body.slice(0, 120));
      } else {
        check('class ' + c.id + ' has a test', false, 'missing test definition');
      }
      continue;
    }
    if (t.parallel) {
      const before = await httpReq(port, 'GET', c.route);
      const b = JSON.parse(before.body).balance;
      const posts = [];
      for (let i = 0; i < t.parallel; i++) posts.push(httpReq(port, 'POST', t.path, { headers: { 'Content-Type': 'text/plain' }, body: t.body }));
      const res = await Promise.all(posts);
      const after = await httpReq(port, 'GET', c.route);
      const a = JSON.parse(after.body).balance;
      const target = b + t.parallel * Number(t.body);
      check('trigger race (final ' + a + ' < ' + target + ')',
        res.every(r => r.status === t.expectStatus) && a < target);
      continue;
    }
    const r = await httpReq(port, t.method, t.path, { headers: t.headers, body: t.body });
    const okStatus = r.status === t.expectStatus;
    const okBody = t.expectInBody ? r.body.includes(t.expectInBody) : true;
    const okHeader = t.expectHeader ? Object.entries(t.expectHeader).every(([k, v]) => (r.headers[k.toLowerCase()] || '') === v) : true;
    check('trigger ' + c.id + ' (status ' + r.status + ')', okStatus && okBody && okHeader,
      'status=' + r.status + (t.expectInBody && !okBody ? ' body-missing=' + t.expectInBody : '')
      + (t.expectHeader && !okHeader ? ' header-mismatch' : '') + ' body=' + r.body.slice(0, 100).replace(/\n/g, ' '));
  }

  // ── eval: empty findings → 0 ──
  const emptyFindings = path.join(tmpBase, 'empty.jsonl');
  fs.writeFileSync(emptyFindings, '');
  const ev0 = JSON.parse(execFileSync(process.execPath, [path.join(TOOLS, 'gen-bench.js'), 'eval', outDir, '--findings', emptyFindings, '--json', '--no-history'], { encoding: 'utf8' }));
  check('eval with no findings → 0 detected', ev0.detected === 0, 'detected=' + ev0.detected);

  // ── matcher: unit (port attribution) ──
  check('unit: explicit bench port matches', matchesBenchPort('get http://127.0.0.1:' + port + '/x', { host: '127.0.0.1' }, port));
  check('unit: explicit OTHER port does not match', !matchesBenchPort('get http://127.0.0.1:3000/x', { host: '127.0.0.1' }, port));
  check('unit: no port cited + loopback host matches', matchesBenchPort('get /api/x?q=1', { host: '127.0.0.1' }, port));
  check('unit: no port cited + localhost matches', matchesBenchPort('get /api/x?q=1', { host: 'localhost' }, port));
  check('unit: no port cited + remote host does not match', !matchesBenchPort('get /api/x?q=1', { host: 'example.com' }, port));
  check('unit: blob lowercases and includes cwe/poc fields',
    findingBlob({ title: 'SQL Injection', cwe: 'CWE-89', poc: 'GET /a?q=UNION' }).includes('cwe-89') && findingBlob({ poc: '/A?q=' }).includes('/a?q='));

  // ── eval: findings nel formato REALE di record-finding.js (host senza porta) ──
  // Il vecchio matcher richiedeva `:<port>` nel blob e segnava MISSED finding reali:
  // regressione dedicata (bug trovato sul bench seed 3412: score 2/15 invece di 12/15).
  const hostShapeFindings = path.join(tmpBase, 'host-shape.jsonl');
  const hostLines = manifest.classes.map(c => JSON.stringify({
    title: c.title, type: c.title, host: '127.0.0.1', endpoint: 'GET ' + c.route,
    poc: 'GET ' + c.route + ' -> 200', severity: c.severity,
    status: 'verified', verify_level: 'proven_impact', cwe: c.cwe,
  }));
  fs.writeFileSync(hostShapeFindings, hostLines.join('\n') + '\n');
  const ev2 = JSON.parse(execFileSync(process.execPath, [path.join(TOOLS, 'gen-bench.js'), 'eval', outDir, '--findings', hostShapeFindings, '--json', '--no-history'], { encoding: 'utf8' }));
  check('eval with record-finding shape (host, no port) → all detected (' + ev2.detected + '/' + manifest.classes.length + ')',
    ev2.detected === manifest.classes.length);

  // ── eval: stessi keyword ma host fuori dal bench → 0 ──
  const wrongHost = path.join(tmpBase, 'wrong-host.jsonl');
  fs.writeFileSync(wrongHost, manifest.classes.map(c => JSON.stringify({
    title: c.title, type: c.title, host: 'example.com', endpoint: 'GET ' + c.route, status: 'verified',
  })).join('\n') + '\n');
  const ev3 = JSON.parse(execFileSync(process.execPath, [path.join(TOOLS, 'gen-bench.js'), 'eval', outDir, '--findings', wrongHost, '--json', '--no-history'], { encoding: 'utf8' }));
  check('eval with matching keywords but foreign host → 0 detected', ev3.detected === 0, 'detected=' + ev3.detected);

  // ── eval: correct findings → all detected ──
  const goodFindings = path.join(tmpBase, 'good.jsonl');
  const lines = manifest.classes.map(c => JSON.stringify({
    id: 'bench-' + c.id, title: c.title, type: c.title,
    target: 'http://127.0.0.1:' + port, endpoint: c.route, severity: c.severity,
    status: 'verified', verify_level: 'proven_impact',
  }));
  fs.writeFileSync(goodFindings, lines.join('\n') + '\n');
  const ev1 = JSON.parse(execFileSync(process.execPath, [path.join(TOOLS, 'gen-bench.js'), 'eval', outDir, '--findings', goodFindings, '--json', '--no-history'], { encoding: 'utf8' }));
  check('eval with correct findings → all detected (' + ev1.detected + '/' + manifest.classes.length + ')',
    ev1.detected === manifest.classes.length);
  check('route-confirmed ≥ all classes', ev1.routeConfirmed >= manifest.classes.length, 'routeConfirmed=' + ev1.routeConfirmed);
  check('verified ≥ all classes', ev1.verified >= manifest.classes.length, 'verified=' + ev1.verified);

  // ── history tracking: una riga jsonl per eval (cwd isolato in tmpBase) ──
  const ev4 = JSON.parse(execFileSync(process.execPath, [path.join(TOOLS, 'gen-bench.js'), 'eval', outDir, '--findings', goodFindings, '--json'], { encoding: 'utf8', cwd: tmpBase }));
  const histPath = path.join(tmpBase, 'reports', 'bench-history.jsonl');
  check('eval appends bench-history.jsonl', fs.existsSync(histPath));
  if (fs.existsSync(histPath)) {
    const hist = fs.readFileSync(histPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
    const last = hist[hist.length - 1];
    check('history entry has trend fields (seed/detectedPct/missed)',
      hist.length === 1 && last.seed === 424242 && typeof last.detectedPct === 'number' && Array.isArray(last.missed),
      'entries=' + hist.length);
    check('--json summary reports history note', typeof ev4.history === 'string' && ev4.history.includes('#1'));
  }

  // ── cleanup ──
  try { child.kill('SIGTERM'); } catch (e) {}
  for (const d of [outDir, outDir2, outDir3]) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (e) {} }
  try { fs.rmSync(tmpBase, { recursive: true, force: true }); } catch (e) {}

  console.log(failures ? '\n' + failures + ' FAILURES' : '\nALL PASS');
  process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error('test crashed: ' + e.stack); process.exit(2); });
