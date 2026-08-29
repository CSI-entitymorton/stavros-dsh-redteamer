#!/usr/bin/env node
// Zero-dependency OFFLINE test for the ondata1 A3 gate extensions in tools/gate.js
// (kinds chain/oracle/evidenceQuote) + record-finding.verifyFindingsChain semantics.
// Stile tools/test-budget.js: PASS/FAIL per caso, exit 1 se almeno un FAIL.
//
//   - nessuna rete, solo stdlib; fixture in mkdtemp; i nuovi check gate accettano un path
//     opzionale così vengono esercitati su file temporanei, mai sullo store reale;
//   - tamper test obbligatorio: un byte manomesso a metà catena fa FALLIRE il check e il
//     prossimo record rifiuta (coperto anche in test-record-finding.js).
//
// Run: node tools/test-gate-chain.js
'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const gate = require('./gate');
const rf = require('./record-finding');
const oracle = require('./oracle');

let pass = 0, fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name} :: ${String(e.message).split('\n')[0]}`); }
}

const ENV_KEYS = ['DSH_WS_ROOT', 'ORACLE_LOG', 'ORACLE_ARTIFACTS'];
const SAVED = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-chain-test-'));
process.env.DSH_WS_ROOT = TMP;
process.env.ORACLE_LOG = path.join(TMP, 'reports', 'tmp', 'oracle-log.jsonl');
process.env.ORACLE_ARTIFACTS = path.join(TMP, 'artifacts', 'oracle');

// Build a properly chained jsonl from plain finding objects (chain fields attached here,
// mirroring what buildChainedLine does at append time).
function chainUp(objects) {
  const lines = [];
  let prev = '0'.repeat(64);
  objects.forEach((o, i) => {
    const f = { ...o, chain: { seq: i + 1, prev_sha256: prev, ts: o.ts || '2026-08-26T00:00:00Z' } };
    const raw = JSON.stringify(f);
    lines.push(raw);
    prev = rf.sha256Hex(raw);
  });
  return lines;
}
function writeJsonl(file, lines) {
  fs.writeFileSync(file, lines.join('\n') + '\n');
}

console.log('# tools/gate.js — A3 chain/oracle/evidenceQuote checks');

// ─── gruppo 1: verifyFindingsChain semantics ───
{
  const A = { severity: 'Low', title: 'a', host: 'h', poc: 'x', status: 'inconclusive' };
  const B = { severity: 'Low', title: 'b', host: 'h', poc: 'x', status: 'confirmed' };
  const C = { severity: 'Low', title: 'c', host: 'h', poc: 'x', status: 'verified' };
  ok('empty store verifies trivially', () => {
    const v = rf.verifyFindingsChain([]);
    assert.deepStrictEqual([v.ok, v.chained, v.legacy], [true, 0, 0]);
  });
  ok('single genesis line ok (prev = 64 zeros)', () => {
    const v = rf.verifyFindingsChain(chainUp([A]));
    assert.strictEqual(v.ok, true);
  });
  ok('three-line chain ok', () => {
    const v = rf.verifyFindingsChain(chainUp([A, B, C]));
    assert.deepStrictEqual([v.ok, v.chained, v.legacy], [true, 3, 0]);
  });
  ok('legacy prefix counted, first chained line anchors to it', () => {
    const legacy1 = JSON.stringify({ severity: 'Low', title: 'old', host: 'h', poc: 'x' });
    const lines = [legacy1].concat(chainUp([{ ...B }]).map((l) => {
      // rebuild seq=2 anchored to legacy line: easiest via buildChainedLine
      return l;
    }));
    lines[1] = rf.buildChainedLine(JSON.parse(lines[1]), [legacy1]);
    const v = rf.verifyFindingsChain(lines);
    assert.deepStrictEqual([v.ok, v.chained, v.legacy], [true, 1, 1]);
  });
  ok('TAMPER mid-chain: one flipped byte fails at child line', () => {
    const lines = chainUp([A, B, C]);
    lines[1] = lines[1].replace('"title":"b"', '"title":"z"');
    const v = rf.verifyFindingsChain(lines);
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /prev_sha256 mismatch/);
    assert.strictEqual(v.index, 2);
  });
  ok('seq gap rejected', () => {
    const lines = chainUp([A, B, C]);
    const f = JSON.parse(lines[2]);
    f.chain.seq = 9;
    lines[2] = JSON.stringify(f);
    const v = rf.verifyFindingsChain(lines);
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /seq gap/);
  });
  ok('genesis with non-zero prev rejected', () => {
    const lines = chainUp([A]);
    const f = JSON.parse(lines[0]);
    f.chain.prev_sha256 = 'f'.repeat(64);
    lines[0] = JSON.stringify(f);
    const v = rf.verifyFindingsChain(lines);
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /prev_sha256 mismatch/);
  });
  ok('unchained line AFTER a chained line rejected (stripped evidence)', () => {
    const lines = chainUp([A, B]);
    lines.push(JSON.stringify({ severity: 'Low', title: 'ghost', host: 'h', poc: 'x', status: 'inconclusive' }));
    const v = rf.verifyFindingsChain(lines);
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /interrupted/);
  });
  ok('unparseable LEGACY line tolerated (hash continuity is raw-text based)', () => {
    const junk = '{"broken json';
    const lines = [junk];
    lines.push(rf.buildChainedLine({ ...B }, [junk]));
    const v = rf.verifyFindingsChain(lines);
    assert.strictEqual(v.ok, true);
  });
}

// ─── gruppo 2: gate.checkChain ───
{
  const absent = path.join(TMP, 'absent.jsonl');
  ok('checkChain on absent file: informational pass', () => {
    const r = gate.checkChain(absent);
    assert.strictEqual(r.ok, true);
    assert.match(r.detail, /nothing chained yet/);
  });
  const goodFile = path.join(TMP, 'good.jsonl');
  writeJsonl(goodFile, chainUp([
    { severity: 'Low', title: 'a', host: 'h', poc: 'x', status: 'inconclusive' },
    { severity: 'Low', title: 'b', host: 'h', poc: 'x', status: 'confirmed' },
  ]));
  ok('checkChain intact reports chained+legacy counts', () => {
    const r = gate.checkChain(goodFile);
    assert.strictEqual(r.ok, true);
    assert.match(r.detail, /intact/);
  });
  ok('checkChain on legacy-prefixed file reports unchained-legacy (informational)', () => {
    const legacy = JSON.stringify({ severity: 'Info', title: 'pre-chain era', host: 'h', poc: 'x' });
    const file = path.join(TMP, 'legacy-prefix.jsonl');
    writeJsonl(file, [legacy, rf.buildChainedLine(
      { severity: 'Low', title: 'b', host: 'h', poc: 'x', status: 'confirmed', ts: 't' }, [legacy])]);
    const r = gate.checkChain(file);
    assert.strictEqual(r.ok, true);
    assert.match(r.detail, /unchained-legacy/);
  });
  const badFile = path.join(TMP, 'bad.jsonl');
  const badLines = chainUp([{ severity: 'Low', title: 'a', host: 'h', poc: 'x', status: 'inconclusive' },
    { severity: 'Low', title: 'b', host: 'h', poc: 'x', status: 'confirmed' }]);
  badLines[0] = badLines[0].replace('"host":"h"', '"host":"H"'); // byte flip on a referenced line
  writeJsonl(badFile, badLines);
  ok('checkChain FAILS on tampered copy', () => {
    const r = gate.checkChain(badFile);
    assert.strictEqual(r.ok, false);
    assert.match(r.detail, /BROKEN/);
    void badLines;
  });
}

// ─── gruppo 3: gate.checkOracle / gate.checkEvidenceQuote ───
{
  const rec = oracle.writeReceipt({ type: 'http-diff', anchor: 'gate-quote-anchor: outcome passed', data: {} });
  assert.ok(rec.ok);
  const goodF = { severity: 'Low', title: 'good-reality', host: 'target.example', poc: 'p',
    status: 'confirmed',
    oracle: { type: 'http-diff', ref: rec.ref, token: rec.token },
    evidence_quote: { file: rec.ref, text: 'gate-quote-anchor: outcome passed' } };
  const hypF = { severity: 'Low', title: 'just-a-hypothesis', host: 'target.example', poc: 'p', status: 'inconclusive' };

  const mixedFile = path.join(TMP, 'mixed.jsonl');
  writeJsonl(mixedFile, [JSON.stringify(goodF), JSON.stringify(hypF)]);
  ok('checkOracle: reality row re-validated against disk passes', () => {
    const r = gate.checkOracle(mixedFile);
    assert.strictEqual(r.ok, true, r.detail);
    assert.match(r.detail, /1\/1 pass/);
  });
  ok('checkEvidenceQuote: verbatim quote passes', () => {
    const r = gate.checkEvidenceQuote(mixedFile);
    assert.strictEqual(r.ok, true, r.detail);
    assert.match(r.detail, /1\/1 pass/);
  });
  ok('hypothesis-only store: checks are informational, not failed', () => {
    const f = path.join(TMP, 'hypo.jsonl');
    writeJsonl(f, [JSON.stringify(hypF)]);
    assert.match(gate.checkOracle(f).detail, /no reality-level/);
    assert.match(gate.checkEvidenceQuote(f).detail, /no reality-level/);
    assert.strictEqual(gate.checkOracle(f).ok, true);
  });

  // Corrupt the receipt artifact ON DISK after recording → gate must catch it NOW.
  const corruptFile = path.join(TMP, 'corrupt.jsonl');
  fs.writeFileSync(rec.file, JSON.stringify({ kind: 'oracle-receipt', type: 'http-diff', token: 'WIPEDOUT000001', anchor: 'gone' }) + '\n');
  writeJsonl(corruptFile, [JSON.stringify(goodF)]);
  ok('checkOracle catches post-hoc artifact corruption', () => {
    const r = gate.checkOracle(corruptFile);
    assert.strictEqual(r.ok, false);
    assert.match(r.detail, /good-reality|token not found/);
  });
  ok('checkEvidenceQuote catches quote whose artifact no longer matches', () => {
    const r = gate.checkEvidenceQuote(corruptFile);
    assert.strictEqual(r.ok, false);
    assert.match(r.detail, /verbatim|substring/);
  });
}

// ─── gruppo 4: report gate definition stays additive ───
{
  ok('report gate keeps original checks, appends SA1 chain/oracle/evidenceQuote, then Ondata-6 tail', () => {
    const kinds = gate.GATES.report.checks.map((c) => c.kind);
    assert.deepStrictEqual(kinds.slice(0, 4), ['findings', 'verify', 'noPending', 'coverage']);
    assert.deepStrictEqual(kinds.slice(4), ['chain', 'oracle', 'evidenceQuote', 'pocReplay', 'chainHead']);
  });
  ok('runGate(report) returns one result per check', () => {
    const r = gate.runGate('report');
    assert.strictEqual(r.gateId, 'report');
    assert.strictEqual(r.results.length, gate.GATES.report.checks.length);
    for (const res of r.results) assert.ok('ok' in res && typeof res.detail === 'string');
  });
  ok('checkScopeNonEmpty accepts dual schema (targets/exclusions superset)', () => {
    const lab = gate.checkScopeNonEmpty({ targets: ['192.168.0.0/24'], exclusions: [] });
    assert.strictEqual(lab.ok, true);
    assert.match(lab.detail, /targets/);
    const classic = gate.checkScopeNonEmpty({ allowed_hosts: ['a.example'], allowed_ips: [] });
    assert.strictEqual(classic.ok, true);
    const empty = gate.checkScopeNonEmpty({ targets: [], exclusions: ['10.0.0.0/8'] });
    assert.strictEqual(empty.ok, false, 'exclusions alone authorize nothing');
  });
}

// ─── gruppo 5: CLI smoke ───
{
  ok('CLI gate status runs green (exit 0)', () => {
    const r = spawnSync(process.execPath, [path.join(__dirname, 'gate.js'), 'status', 'host'], { encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stderr);
  });
}

for (const k of ENV_KEYS) {
  if (SAVED[k] === undefined) delete process.env[k]; else process.env[k] = SAVED[k];
}
console.log(`\ngate-chain: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
