#!/usr/bin/env node
// Zero-dependency OFFLINE test for tools/oracle.js (A1 mechanical oracle, fail-closed).
// Stile tools/test-budget.js: PASS/FAIL per caso, exit 1 se almeno un FAIL.
//
//   - nessuna rete, solo stdlib; fixture in mkdtemp (mai il workspace reale);
//   - env isolation per-run: DSH_WS_ROOT / ORACLE_LOG / ORACLE_ARTIFACTS / OOB_MARKERS / OOB_HITS;
//   - avversariali: traversal, absolute path, backslash, symlink escape, token assente,
//     type mismatch, JSON invalido, riga fuori range, ref generico.
//
// Run: node tools/test-oracle.js
'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TOOL = path.join(__dirname, 'oracle.js');
const oracle = require('./oracle');

let pass = 0, fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name} :: ${String(e.message).split('\n')[0]}`); }
}

const ENV_KEYS = ['DSH_WS_ROOT', 'ORACLE_LOG', 'ORACLE_ARTIFACTS', 'OOB_MARKERS', 'OOB_HITS'];

function newWs(tag) {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'oracle-test-' + tag + '-'));
  const env = {};
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.DSH_WS_ROOT = ws;
  process.env.ORACLE_LOG = path.join(ws, 'reports', 'tmp', 'oracle-log.jsonl');
  process.env.ORACLE_ARTIFACTS = path.join(ws, 'artifacts', 'oracle');
  for (const k of ENV_KEYS) env[k] = process.env[k];
  return { ws, env };
}

function runCli(args, extraEnv) {
  const env = { ...process.env, ...(extraEnv || {}) };
  return spawnSync(process.execPath, [TOOL].concat(args), { encoding: 'utf8', env });
}

console.log('# tools/oracle.js — A1 mechanical oracle');

// ─── gruppo 1: CLI record → append-only log + handle ref ───
{
  const { ws, env } = newWs('rec');
  let r = runCli(['record', JSON.stringify({ type: 'http-diff', token: 'abcd1234efgh5678', note: 'diff control vs injected' })], env);
  ok('CLI record valid exits 0', () => assert.strictEqual(r.status, 0));
  let out = JSON.parse(r.stdout);
  ok('CLI record returns usable ref handle', () => assert.match(out.ref, /^reports\/tmp\/oracle-log\.jsonl#1$/));
  const logLines = () => fs.readFileSync(env.ORACLE_LOG, 'utf8').split('\n').filter(Boolean);
  ok('log line appended with ts/type/token', () => {
    const l = JSON.parse(logLines()[0]);
    assert.strictEqual(l.type, 'http-diff');
    assert.strictEqual(l.token, 'abcd1234efgh5678');
    assert.match(l.ts, /^\d{4}-\d{2}-\d{2}T/);
  });
  r = runCli(['record', JSON.stringify({ type: 'oob', token: '0123456789abcdef' })], env);
  out = JSON.parse(r.stdout);
  ok('second record anchors to line #2', () => assert.strictEqual(out.ref, 'reports/tmp/oracle-log.jsonl#2'));
  ok('invalid type rejected, log untouched', () => {
    const r2 = runCli(['record', JSON.stringify({ type: 'vibes', token: 'abcd1234efgh5678' })], env);
    assert.notStrictEqual(r2.status, 0);
    assert.strictEqual(logLines().length, 2);
  });
  ok('short token rejected', () => {
    const r2 = runCli(['record', JSON.stringify({ type: 'script', token: 'ab' })], env);
    assert.notStrictEqual(r2.status, 0);
    assert.match(r2.stdout, /token/);
  });
  ok('malformed JSON argument rejected', () => {
    const r2 = runCli(['record', '{oops'], env);
    assert.notStrictEqual(r2.status, 0);
  });
}

// ─── gruppo 2: validateOracle positive (log / artifact / OOB) ───
{
  const { ws } = newWs('pos');
  fs.mkdirSync(path.join(ws, 'reports', 'tmp'), { recursive: true });
  fs.writeFileSync(oracle.ORACLE_LOG(),
    JSON.stringify({ ts: 't1', type: 'http-diff', token: 'tokhttpdiff0001' }) + '\n' +
    JSON.stringify({ ts: 't2', type: 'console', token: 'tokconsole000001' }) + '\n');
  const rec = oracle.writeReceipt({ type: 'script', anchor: 'outcome passed: 3/3', data: { detail: 'x' } });
  ok('writeReceipt writes artifact under artifacts/oracle', () => {
    assert.ok(rec.ok);
    assert.ok(fs.existsSync(rec.file));
    assert.match(rec.ref, /^artifacts\/oracle\/[0-9a-f]{16}\.json$/);
  });
  ok('log ref with #N validates', () =>
    assert.strictEqual(oracle.validateOracle({ type: 'http-diff', ref: 'reports/tmp/oracle-log.jsonl#1', token: 'tokhttpdiff0001' }), null));
  ok('log ref without #N scans by token+type', () =>
    assert.strictEqual(oracle.validateOracle({ type: 'console', ref: 'reports/tmp/oracle-log.jsonl', token: 'tokconsole000001' }), null));
  ok('artifact receipt ref validates', () =>
    assert.strictEqual(oracle.validateOracle({ type: 'script', ref: rec.ref, token: rec.token }), null));

  // OOB markers/hits written by tools/oob.js (same shape) — read-only consumption.
  fs.mkdirSync(path.join(ws, 'reports', 'oob'), { recursive: true });
  fs.writeFileSync(path.join(ws, 'reports', 'oob', 'markers.jsonl'),
    JSON.stringify({ ts: 'm1', token: 'oobmarkerdeadbeef', url: 'http://127.0.0.1:9099/oobmarkerdeadbeef' }) + '\n');
  fs.writeFileSync(path.join(ws, 'reports', 'oob', 'hits.jsonl'),
    JSON.stringify({ ts: 'h1', method: 'GET', url: '/oobhitcafebabe0000', source_ip: '10.0.0.1' }) + '\n');
  ok('OOB marker accepted as oob-type ref', () =>
    assert.strictEqual(oracle.validateOracle({ type: 'oob', ref: 'reports/oob/markers.jsonl', token: 'oobmarkerdeadbeef' }), null));
  ok('OOB hit accepted as oob-type ref with #line', () =>
    assert.strictEqual(oracle.validateOracle({ type: 'oob', ref: 'reports/oob/hits.jsonl#1', token: 'oobhitcafebabe0000' }), null));
}

// ─── gruppo 3: validateOracle adversarial (fail-closed) ───
{
  const { ws } = newWs('adv');
  fs.mkdirSync(path.join(ws, 'reports', 'tmp'), { recursive: true });
  fs.mkdirSync(path.join(ws, 'artifacts', 'oracle'), { recursive: true });
  fs.writeFileSync(oracle.ORACLE_LOG(), JSON.stringify({ ts: 't', type: 'console', token: 'goodtoken0000001' }) + '\n');
  fs.writeFileSync(path.join(ws, 'artifacts', 'oracle', 'ok.json'), JSON.stringify({ type: 'script', anchor: 'zz' }) + '\n');
  fs.writeFileSync(path.join(ws, 'artifacts', 'oracle', 'bad.json'), '{not json');
  fs.writeFileSync(path.join(ws, 'artifacts', 'oracle', 'othertype.json'), JSON.stringify({ type: 'console', x: 'toknotpresenthere' }) + '\n');
  fs.writeFileSync(path.join(ws, 'notes.txt'), 'generic workspace file');

  ok('token absent from artifact rejected', () =>
    assert.match(oracle.validateOracle({ type: 'script', ref: 'artifacts/oracle/othertype.json', token: 'absenttoken00001' }) || '', /token not found/));
  ok('artifact JSON invalid rejected', () =>
    assert.match(oracle.validateOracle({ type: 'script', ref: 'artifacts/oracle/bad.json', token: 'whatevertoken123' }) || '', /JSON invalid/));
  ok('artifact embedded type mismatch rejected', () => {
    // artifact contains the token but declares a different type than the oracle claims
    fs.writeFileSync(path.join(ws, 'artifacts', 'oracle', 'mismatch.json'), JSON.stringify({ type: 'oob', note: 'xxmismatchtoken99' }) + '\n');
    const e = oracle.validateOracle({ type: 'script', ref: 'artifacts/oracle/mismatch.json', token: 'xxmismatchtoken99' });
    assert.match(e || '', /does not match artifact type/);
  });
  ok('log line type mismatch rejected', () =>
    assert.match(oracle.validateOracle({ type: 'http-diff', ref: 'reports/tmp/oracle-log.jsonl#1', token: 'goodtoken0000001' }) || '', /does not match logged type/));
  ok("path traversal ('..') rejected", () =>
    assert.match(oracle.validateOracle({ type: 'console', ref: '../outside/log.jsonl#1', token: 'goodtoken0000001' }) || '', /traversal/));
  ok('absolute ref rejected', () =>
    assert.match(oracle.validateOracle({ type: 'console', ref: '/etc/passwd', token: 'goodtoken0000001' }) || '', /workspace-relative/));
  ok('backslash separator rejected', () =>
    assert.match(oracle.validateOracle({ type: 'console', ref: 'reports\\tmp\\x.jsonl', token: 'goodtoken0000001' }) || '', /separators/));
  ok('symlink escaping the workspace rejected', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'oracle-outside-'));
    const secret = path.join(outside, 'secret.json');
    fs.writeFileSync(secret, '{"leak":true}');
    fs.symlinkSync(secret, path.join(ws, 'artifacts', 'oracle', 'escape.json'));
    const e = oracle.validateOracle({ type: 'script', ref: 'artifacts/oracle/escape.json', token: 'anythinggoes1234' });
    assert.match(e || '', /outside the workspace/);
  });
  ok('generic workspace file as ref rejected', () =>
    assert.match(oracle.validateOracle({ type: 'console', ref: 'notes.txt', token: 'goodtoken0000001' }) || '', /must point to/));
  ok('nonexistent ref rejected', () =>
    assert.match(oracle.validateOracle({ type: 'console', ref: 'artifacts/oracle/nope.json', token: 'goodtoken0000001' }) || '', /unreadable|ENOENT/));
  ok('#N beyond EOF rejected', () =>
    assert.match(oracle.validateOracle({ type: 'console', ref: 'reports/tmp/oracle-log.jsonl#99', token: 'goodtoken0000001' }) || '', /not found/));
  ok('OOB ref requires type "oob"', () => {
    fs.mkdirSync(path.join(ws, 'reports', 'oob'), { recursive: true });
    fs.writeFileSync(path.join(ws, 'reports', 'oob', 'markers.jsonl'),
      JSON.stringify({ ts: 'm', token: 'markerfortest9999', url: 'u' }) + '\n');
    const e = oracle.validateOracle({ type: 'console', ref: 'reports/oob/markers.jsonl', token: 'markerfortest9999' });
    assert.match(e || '', /requires type "oob"/);
  });
  ok('scan finds no matching token+type pair', () =>
    assert.match(oracle.validateOracle({ type: 'console', ref: 'reports/tmp/oracle-log.jsonl', token: 'missingtotally01' }) || '', /no oracle-log line/));
}

// ─── gruppo 4: ORACLE_LOG fuori workspace → fail-closed anche in scrittura ───
{
  const { env } = newWs('split');
  const otherWs = fs.mkdtempSync(path.join(os.tmpdir(), 'oracle-otherws-'));
  const r = runCli(['record', JSON.stringify({ type: 'script', token: 'crosswstoken0001' })],
    { ...env, ORACLE_LOG: path.join(otherWs, 'elsewhere.jsonl') });
  ok('record refuses log outside DSH_WS_ROOT', () => {
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stdout, /fail-closed|outside/);
  });
}

// ─── gruppo 5: CLI check + predicate ───
{
  const { ws, env } = newWs('chk');
  const rec = oracle.writeReceipt({ type: 'http-diff', anchor: 'anchor here 1234', data: {} });
  const goodF = { title: 'x', oracle: { type: 'http-diff', ref: rec.ref, token: rec.token } };
  let r = runCli(['check', JSON.stringify(goodF)], env);
  ok('CLI check valid oracle exits 0', () => {
    assert.strictEqual(r.status, 0);
    assert.strictEqual(JSON.parse(r.stdout).ok, true);
  });
  r = runCli(['check', JSON.stringify({ title: 'y' })], env);
  ok('CLI check missing oracle exits !=0 with hint', () => {
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stdout, /no oracle field/);
  });
  ok('claimingReality truth table', () => {
    assert.strictEqual(oracle.claimingReality({ status: 'confirmed' }), true);
    assert.strictEqual(oracle.claimingReality({ status: 'verified' }), true);
    assert.strictEqual(oracle.claimingReality({ status: 'inconclusive' }), false);
    assert.strictEqual(oracle.claimingReality({ verify_level: 'exploited' }), true);
    assert.strictEqual(oracle.claimingReality({ verify_level: 'proven_impact' }), true);
    assert.strictEqual(oracle.claimingReality({ verify_level: 'suspected' }), false);
    assert.strictEqual(oracle.claimingReality({}), false);
    assert.strictEqual(oracle.claimingReality(null), false);
  });
  ok('GENESIS is 64 zeros; TOKEN_RE bounds', () => {
    assert.strictEqual(oracle.GENESIS, '0'.repeat(64));
    assert.ok(oracle.TOKEN_RE.test('12345678'));
    assert.ok(!oracle.TOKEN_RE.test('1234567'));       // too short
    assert.ok(!oracle.TOKEN_RE.test('has space 1234')); // whitespace
  });
  ok('parseRef splits #line suffix', () => {
    assert.deepStrictEqual(oracle.parseRef('a/b.jsonl#12'), { p: 'a/b.jsonl', line: 12 });
    assert.deepStrictEqual(oracle.parseRef('a/b.jsonl'), { p: 'a/b.jsonl', line: null });
  });
  void ws;
}

// env restore (the suite runner executes tests sequentially in-process)
for (const k of ENV_KEYS) delete process.env[k];

console.log(`\noracle: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
