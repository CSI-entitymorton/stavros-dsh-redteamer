#!/usr/bin/env node
// Ondata 2 — SB3 test suite (B2 + B3 + B7): coverage-section nel report HTML, confidence
// deterministica, poc-replay. Offline: fixture in mkdtemp, SCOPE_JSON/EVIDENCE/EXP overrides,
// script python3 locali che stampano i marker della convenzione (exit 0 = REPRODUCED).
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const assert = require('assert');

let pass = 0; let fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}: ${e.message}`); }
}
async function okAsync(name, fn) {
  try { await fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}: ${e.message}`); }
}

const WS = path.join(__dirname, '..');
const RH = path.join(WS, 'tools', 'report-html.js');
const PR = path.join(WS, 'tools', 'poc-replay.js');

async function main() {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'sb3-'));
  const reportsDir = path.join(T, 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });
  const findingsFile = path.join(T, 'findings.jsonl');

  // Fixture findings: verified con oracle+reproductions, confirmed legacy, inconclusive (FP-ish),
  // una title ostile per l'escape test. Host unico target.example.
  const rows = [
    { severity: 'High', title: 'sqli in login', host: 'target.example', status: 'verified',
      oracle: { type: 'oob', ref: 'reports/tmp/oracle-log.jsonl#1', token: 'tok1234567890' },
      verify: { runs: 3, independent: true }, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    { severity: 'Medium', title: '<script>alert(1)</script> reflected xss', host: 'target.example', status: 'confirmed',
      oracle: { type: 'script', ref: 'reports/tmp/oracle-log.jsonl#2', token: 'tok2234567890' } },
    { severity: 'Low', title: 'suspected idor', host: 'target.example', status: 'inconclusive' },
    { severity: 'Info', title: 'other host row', host: 'other.example', status: 'triggered' },
  ];
  fs.writeFileSync(findingsFile, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');

  // Map file con skip_reason (B2 contract) + legacy numeric entry.
  fs.writeFileSync(path.join(reportsDir, 'target.example-map.json'), JSON.stringify({
    sqli: { candidates: 4 },
    xss: { candidates: 2, skip_reason: 'probe interrotta: WAF block (rate)' },
    authn: 3,
    ssrf: { candidates: 1 },
    csrf: 0,
    crypto: { candidates: 0, skip_reason: 'fuori perimetro dichiarato dall operatore' },
  }));

  console.log('SB3/B3: confidence deterministico');
  ok('formula: base oracolo + riproduzioni + indipendenza, clamp [0,1]', () => {
    const m = require(RH);
    const c1 = m.confidenceOf({ oracle: { type: 'oob' }, verify: { runs: 3, independent: true } });
    assert.strictEqual(c1.score, 1.0); // 0.9 + 0.05*2 + 0.05 → clampato a 1
    assert.strictEqual(c1.label, 'high');
    const c2 = m.confidenceOf({ oracle: { type: 'http-diff' }, verify: { runs: 1 } });
    assert.strictEqual(c2.score, 0.85); // nessun bonus
    const c3 = m.confidenceOf({ status: 'confirmed' }); // reality claim senza oracolo (legacy)
    assert.strictEqual(c3.score, 0.6);
    const c4 = m.confidenceOf({ status: 'inconclusive' }); // solo ipotesi
    assert.strictEqual(c4.score, 0.35);
    assert.strictEqual(c4.label, 'low');
    const c5 = m.confidenceOf({ oracle: { type: 'script' }, verify: { runs: 2, oracle_refs: ['a#1', 'a#2'] } });
    assert.strictEqual(c5.score, 0.85); // 0.75 + 0.05 + 0.05(indipendenza da 2 ref distinte)
    // runs cap: oltre 5 riproduzioni il bonus si ferma a +0.20
    const c6 = m.confidenceOf({ oracle: { type: 'console' }, verify: { runs: 99 } });
    assert.strictEqual(c6.score, 1.0);
  });
  ok('determinismo: stesso input -> stesso output (100 iterazioni)', () => {
    const m = require(RH);
    const f = { oracle: { type: 'http-diff' }, verify: { runs: 4, independent: true } };
    const first = JSON.stringify(m.confidenceOf(f));
    for (let i = 0; i < 100; i++) assert.strictEqual(JSON.stringify(m.confidenceOf(f)), first);
  });

  console.log('SB3/B2: sezione «Copertura & accuratezza»');
  ok('coverageSummary: candidati→verificati→FP scartati→untested+causa', () => {
    const m = require(RH);
    const { buildMatrix } = require(path.join(WS, 'tools', 'coverage.js'));
    const mat = buildMatrix('target.example', { reportsDir, findingsFile });
    const fh = rows.filter((r) => r.host === 'target.example');
    const s = m.coverageSummary(mat, fh);
    assert.strictEqual(s.candidatesTotal, 10); // 4+2+3+1 (+csrf 0, crypto 0)
    assert.strictEqual(s.verified, 2);         // verified + confirmed
    assert.strictEqual(s.fpDiscarded, 1);      // inconclusive
    const untestedMap = Object.fromEntries(s.untested.map((u) => [u.class, u.cause]));
    // ssrf (candidature>0) è TESTED, non untested; sqli/xss hanno findings; authn è tested.
    for (const c of ['sqli', 'xss', 'authn', 'ssrf']) {
      assert.strictEqual(untestedMap[c], undefined, `${c} non deve essere in untested`);
    }
    // classi assenti dalla map -> n-a SILZENZIOSE (semantica baseline di coverage.js):
    // restano FUORI da untested (solo skip esplicito o missed reale ci entrano).
    assert.strictEqual(untestedMap.authz, undefined);
    // n-a con skip_reason ESPLICITO -> untested con la sua causa (B2 contract)
    assert.match(untestedMap.crypto, /fuori perimetro/);
    const xssRow = mat.rows.find((r) => r.class === 'xss');
    assert.strictEqual(xssRow.skip_reason, 'probe interrotta: WAF block (rate)');
  });
  ok('buildMatrix espone skip_reason e resta retrocompatibile coi numeri', () => {
    const { buildMatrix } = require(path.join(WS, 'tools', 'coverage.js'));
    const m = buildMatrix('target.example', { reportsDir, findingsFile });
    const xss = m.rows.find((r) => r.class === 'xss');
    assert.strictEqual(xss.skip_reason, 'probe interrotta: WAF block (rate)');
    const authn = m.rows.find((r) => r.class === 'authn');
    assert.strictEqual(authn.candidates, 3);
    assert.strictEqual(authn.skip_reason, null); // legacy numeric
  });

  console.log('SB3/B2: buildHtml end-to-end');
  ok('HTML contiene la sezione, i conteggi giusti e l\'escape anti-XSS', () => {
    const m = require(RH);
    const findings = rows.map((r) => Object.assign(m.enrichFinding(r)));
    const covHosts = [];
    const { buildMatrix } = require(path.join(WS, 'tools', 'coverage.js'));
    for (const h of ['target.example']) {
      const mat = buildMatrix(h, { reportsDir, findingsFile });
      covHosts.push({ matrix: mat, summary: m.coverageSummary(mat, findings.filter((f) => f.host === h)) });
    }
    const html = m.buildHtml({
      findings: findings.filter((f) => f.host === 'target.example'),
      targets: [], chains: [], sploitByCve: {},
      coverage: { hosts: covHosts, totals: { candidatesTotal: 10, verified: 2, fpDiscarded: 1, untestedTotal: covHosts[0].summary.untested.length } },
      generatedAt: new Date().toISOString(),
    });
    assert.ok(html.includes('Copertura &amp; accuratezza'));
    assert.ok(html.includes('<strong>10</strong> candidati'), 'candidati totali');
    assert.ok(html.includes('<strong>2</strong> verificati'));
    assert.ok(html.includes('<strong>1</strong> FP/inconclusivi scartati'));
    assert.ok(html.includes('probe interrotta: WAF block (rate)'), 'causa skip_reason mostrata');
    // confidence accanto al CVSS: oob+3 runs+independent → clamp 100% high
    assert.ok(html.includes('conf-high'));
    assert.ok(html.includes('100% high'), 'confidence 100% high attesa per la riga oob');
    // escape del titolo ostile
    assert.ok(!html.includes('<script>alert(1)</script>'), 'XSS non escapato!');
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    // colonna Confidence presente nell'intestazione
    assert.ok(html.includes('<th>Confidence</th>'));
  });

  console.log('SB3/B7: poc-replay');
  const scopeFile = path.join(T, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({ targets: ['target.example'] }));
  const expDir = path.join(T, 'exp');
  fs.mkdirSync(expDir, { recursive: true });
  // I nomi file derivano con LA STESSA funzione del tool (findingId) — niente guessing.
  const mPR = require(PR);
  const idSqli = mPR.findingId(rows[0]);
  const idXss = mPR.findingId(rows[1]);
  const okScript = path.join(expDir, `${idSqli}.py`);
  fs.writeFileSync(okScript, "#!/usr/bin/env python3\nimport sys\nprint('REPRODUCED (HTTP 200)')\nsys.exit(0)\n");
  const koScript = path.join(expDir, `${idXss}.py`);
  fs.writeFileSync(koScript, "#!/usr/bin/env python3\nimport sys\nprint('NOT reproduced (HTTP 403)')\nsys.exit(1)\n");
  const eiFile = path.join(T, 'evidence-index.md');

  function runReplay(args, envExtra) {
    return spawnSync('node', [PR, ...args], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, { SCOPE_JSON: scopeFile, EVIDENCE_INDEX_FILE: eiFile, FINDINGS_JSONL: findingsFile }, envExtra || {}),
      cwd: WS,
    });
  }

  await okAsync('functional: replay OK -> exit 0 + riga evidence appendita SENZA target', async () => {
    const before = (() => { try { return fs.readFileSync(eiFile, 'utf8').split('\n').filter(Boolean).length; } catch { return 0; } })();
    const r = runReplay([idSqli, '-u', 'http://target.example/', '--exp-dir', expDir, '--json']);
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    const j = JSON.parse(r.stdout);
    assert.strictEqual(j.marker, 'REPRODUCED');
    assert.strictEqual(j.exit, 0);
    const lines = fs.readFileSync(eiFile, 'utf8').split('\n').filter(Boolean);
    assert.strictEqual(lines.length, before + 1);
    const row = lines[lines.length - 1];
    assert.match(row, new RegExp(`poc-replay id=${idSqli} exit=0 marker=REPRODUCED`));
    assert.ok(!row.includes('target.example'), 'target NON registrato di default');
  });
  await okAsync('functional: replay FALLITO -> exit 1 ma evidenza ONESTA registrata', async () => {
    const r = runReplay([idXss, '-u', 'http://target.example/', '--exp-dir', expDir, '--json']);
    assert.strictEqual(r.status, 1);
    const j = JSON.parse(r.stdout);
    assert.strictEqual(j.marker, 'NOT_REPRODUCED');
    const lastLine = fs.readFileSync(eiFile, 'utf8').split('\n').filter(Boolean).pop();
    assert.match(lastLine, /exit=1 marker=NOT_REPRODUCED/);
  });
  await okAsync('--latest risolve il finding verificato più recente', async () => {
    const r = runReplay(['--latest', '-u', 'http://target.example/', '--exp-dir', expDir]);
    assert.strictEqual(r.status, 0, r.stderr);
  });
  await okAsync('avversariale: target fuori scope -> NESSUN exec, NESSUNA evidenza', async () => {
    const before = fs.readFileSync(eiFile, 'utf8').split('\n').filter(Boolean).length;
    const r = runReplay(['--latest', '-u', 'http://evil.example/', '--exp-dir', expDir]);
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /out of scope|invalid/);
    assert.strictEqual(fs.readFileSync(eiFile, 'utf8').split('\n').filter(Boolean).length, before);
  });
  await okAsync('avversariale: scope illeggibile -> fail-closed', async () => {
    const r = spawnSync('node', [PR, '--latest', '-u', 'http://target.example/', '--exp-dir', expDir], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, { SCOPE_JSON: path.join(T, 'missing-scope.json'), EVIDENCE_INDEX_FILE: eiFile, FINDINGS_JSONL: findingsFile }),
      cwd: WS,
    });
    assert.strictEqual(r.status, 1);
    // hardened scope-guard denies cleanly on unreadable/missing scope (no ENOENT crash)
    assert.match(r.stderr, /out of scope|fail-closed/);
  });
  await okAsync('avversariale: reproducer mancante -> errore chiaro, zero spawn', async () => {
    const before = fs.readFileSync(eiFile, 'utf8').split('\n').filter(Boolean).length;
    const idNoExp = mPR.findingId(rows[2]); // finding ESISTENTE ma senza .py su disco
    const r = spawnSync('node', [PR, idNoExp, '-u', 'http://target.example/', '--exp-dir', path.join(T, 'empty-exp')], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, { SCOPE_JSON: scopeFile, EVIDENCE_INDEX_FILE: eiFile, FINDINGS_JSONL: findingsFile }),
      cwd: WS,
    });
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /not found/);
    assert.strictEqual(fs.readFileSync(eiFile, 'utf8').split('\n').filter(Boolean).length, before);
  });
  ok('checkPocReplays (proposta kind gate): verified senza exp = missingExp', () => {
    const res = mPR.checkPocReplays(rows, { expDir });
    // verified: solo la prima riga (status verified) → ha lo script
    assert.deepStrictEqual(res.checked, [idSqli]);
    assert.strictEqual(res.ok, true);
    const extra = Object.assign({}, rows[0], { title: 'no exp here', status: 'verified' });
    const res2 = mPR.checkPocReplays([...rows, extra], { expDir });
    assert.strictEqual(res2.ok, false);
    assert.deepStrictEqual(res2.missingExp, [mPR.findingId(extra)]);
  });
  ok('marker extraction pura: testo > euristica exit', () => {
    const m = require(PR);
    assert.strictEqual(m.extractMarker('REPRODUCED ok', 0), 'REPRODUCED');
    assert.strictEqual(m.extractMarker('NOT reproduced today', 1), 'NOT_REPRODUCED');
    assert.strictEqual(m.extractMarker('', 0), 'EXIT_0');
    assert.strictEqual(m.extractMarker('', 3), 'NO_MARKER');
  });

  try { fs.rmSync(T, { recursive: true, force: true }); } catch {}

  console.log(`\nsb3: ${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
