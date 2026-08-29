#!/usr/bin/env node
// Zero-dependency OFFLINE test for the ondata1 A1/A2/A3 gates in tools/record-finding.js.
// Stile tools/test-budget.js: PASS/FAIL per caso, exit 1 se almeno un FAIL.
//
//   - nessuna rete, solo stdlib; fixture in mkdtemp; mai il workspace reale;
//   - env isolation: FINDINGS_JSONL / LOOT_JSONL / FINDINGS_TAB_DB / DSH_WS_ROOT /
//     ORACLE_LOG / ORACLE_ARTIFACTS;
//   - TEST FUNZIONALE OBBLIGATORIO A1: confirmed SENZA oracolo = FALLIRE (exit≠0),
//     artefatto via `node tools/oracle.js record` + record CON oracle = PASSARE (exit 0).
//
// Run: node tools/test-record-finding.js
'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RF = path.join(__dirname, 'record-finding.js');
const ORACLE = path.join(__dirname, 'oracle.js');
const rf = require('./record-finding');
const oracle = require('./oracle');
const { validateQuote } = require('./evidence-quote');

let pass = 0, fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name} :: ${String(e.message).split('\n')[0]}`); }
}

const ENV_KEYS = ['FINDINGS_JSONL', 'LOOT_JSONL', 'FINDINGS_TAB_DB', 'DSH_WS_ROOT', 'ORACLE_LOG', 'ORACLE_ARTIFACTS'];
const SAVED = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'rf-test-'));
const FINDINGS = path.join(TMP, 'findings.jsonl');
process.env.FINDINGS_JSONL = FINDINGS;
process.env.LOOT_JSONL = path.join(TMP, 'loot.jsonl');
process.env.FINDINGS_TAB_DB = path.join(TMP, 'tab.db'); // keep the real GUI tab untouched
process.env.DSH_WS_ROOT = TMP;
process.env.ORACLE_LOG = path.join(TMP, 'reports', 'tmp', 'oracle-log.jsonl');
process.env.ORACLE_ARTIFACTS = path.join(TMP, 'artifacts', 'oracle');

function rows(file) {
  return fs.existsSync(file || FINDINGS)
    ? fs.readFileSync(file || FINDINGS, 'utf8').split('\n').filter(Boolean)
    : [];
}
function base(over) {
  return Object.assign({ severity: 'Info', title: 't', host: 'target.example', poc: 'p' }, over);
}
// Compliant reality finding: receipt artifact + oracle + exact quote from the same artifact.
let receiptN = 0;
function withReceipt(over) {
  const f = base(Object.assign({ status: 'confirmed' }, over));
  const rec = oracle.writeReceipt({ type: 'http-diff', anchor: `anchor-${f.title}-${++receiptN}: outcome passed`, data: { detail: 'test' } });
  assert.ok(rec.ok, 'receipt write failed in fixture setup');
  f.oracle = { type: 'http-diff', ref: rec.ref, token: rec.token };
  f.evidence_quote = { file: rec.ref, text: `anchor-${f.title}-${receiptN}: outcome passed` };
  return f;
}
function runNode(tool, args, extraEnv) {
  return spawnSync(process.execPath, [tool].concat(args), { encoding: 'utf8', env: { ...process.env, ...(extraEnv || {}) } });
}
function restoreEnvAndExit(code) {
  for (const k of ENV_KEYS) {
    if (SAVED[k] === undefined) delete process.env[k]; else process.env[k] = SAVED[k];
  }
  console.log(`\nrecord-finding: ${pass} pass, ${fail} fail`);
  process.exit(code);
}

(async () => {
  console.log('# tools/record-finding.js — A1 oracle / A2 quote / A3 chain');

  // ─── gruppo 1: A1 functional gate ───
  {
    fs.rmSync(FINDINGS, { force: true });
    let r = runNode(RF, [JSON.stringify(base({ title: 'no-oracle', status: 'confirmed' }))]);    ok('FUNCTIONAL: confirmed WITHOUT oracle fails (exit != 0)', () => {
      assert.notStrictEqual(r.status, 0);
      const out = JSON.parse(r.stdout);
      assert.match(out.error, /mechanical oracle/);
    });
    ok('FUNCTIONAL: rejected row never touches findings.jsonl', () => assert.strictEqual(rows().length, 0));

    // generate a real artifact through the oracle tool, then record WITH a valid oracle
    r = runNode(ORACLE, ["record", JSON.stringify({ type: "script", token: "functok1234567890", note: "functional test artifact" })]);
    assert.strictEqual(r.status, 0, 'oracle record CLI failed');
    const ref = JSON.parse(r.stdout).ref; // reports/tmp/oracle-log.jsonl#N
    const good = base({ title: 'with-oracle', status: 'confirmed',
      oracle: { type: 'script', ref, token: 'functok1234567890' },
      evidence_quote: { file: 'reports/tmp/oracle-log.jsonl', text: 'functok1234567890' } });
    r = runNode(RF, [JSON.stringify(good)]);
    ok('FUNCTIONAL: confirmed WITH valid oracle+quote passes (exit 0)', () => {
      assert.strictEqual(r.status, 0, r.stdout + r.stderr);
      assert.ok(JSON.parse(r.stdout).ok);
    });
    ok('FUNCTIONAL: row present in findings.jsonl', () => {
      assert.strictEqual(rows().length, 1);
      assert.strictEqual(JSON.parse(rows()[0]).title, 'with-oracle');
    });
  }

  // ─── gruppo 2: no silent default — explicit lanes only ───
  {
    fs.rmSync(FINDINGS, { force: true });
    ok('missing status rejected with actionable roads', () => {
      const r = rf.record(JSON.stringify(base({ title: 'nostatus' })));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /status is required/);
      assert.match(r.error, /inconclusive/);
      assert.match(r.error, /suspected/);
      assert.match(r.error, /oracle/);
    });
    ok('hypothesis lane: status inconclusive, no oracle needed', () =>
      assert.strictEqual(rf.record(JSON.stringify(base({ title: 'hyp1', status: 'inconclusive' }))).ok, true));
    ok('hypothesis lane: verify_level suspected/triggered pass', () => {
      assert.ok(rf.record(JSON.stringify(base({ title: 'hyp2', status: 'inconclusive', verify_level: 'suspected' }))).ok);
      assert.ok(rf.record(JSON.stringify(base({ title: 'hyp3', status: 'inconclusive', verify_level: 'triggered' }))).ok);
    });
    ok('reality level exploited without oracle rejected', () => {
      const r = rf.record(JSON.stringify(base({ title: 'exp1', status: 'inconclusive', verify_level: 'exploited' })));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /mechanical oracle/);
    });
    ok('proven_impact without oracle rejected', () => {
      const r = rf.record(JSON.stringify(base({ title: 'pi1', status: 'verified', verify_level: 'proven_impact' })));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /mechanical oracle/);
    });
    ok('invalid oracle object rejected even on hypothesis rows', () => {
      const r = rf.record(JSON.stringify(base({ title: 'badoracle', status: 'inconclusive', oracle: { type: 'nope' } })));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /invalid oracle/);
    });
    ok('severity ceiling still enforced (High > suspected cap)', () => {
      const r = rf.record(JSON.stringify(base({ title: 'ceil', severity: 'High', status: 'inconclusive', verify_level: 'suspected' })));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /exceeds verify_level/);
    });
  }

  // ─── gruppo 3: A2 evidence_quote ───
  {
    fs.rmSync(FINDINGS, { force: true });
    ok('reality claim without quote rejected (diagnostics are NOT evidence)', () => {
      const f = withReceipt({ title: 'noq' });
      delete f.evidence_quote;
      f.diagnostics = { model_summary: 'looks totally exploited to me' };
      const r = rf.record(JSON.stringify(f));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /evidence_quote/);
    });
    ok('paraphrased quote rejected byte-per-byte', () => {
      const f = withReceipt({ title: 'para' });
      f.evidence_quote.text += ' (roughly)';
      const r = rf.record(JSON.stringify(f));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /verbatim|substring/);
    });
    ok('quote file traversal rejected', () => {
      const f = withReceipt({ title: 'outside' });
      f.evidence_quote.file = '../../../etc/passwd';
      const r = rf.record(JSON.stringify(f));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /traversal/);
    });
    ok('quote of missing file rejected', () => {
      const f = withReceipt({ title: 'missingfile' });
      f.evidence_quote.file = 'artifacts/oracle/__nope__.json';
      const r = rf.record(JSON.stringify(f));
      assert.strictEqual(r.ok, false);
      assert.match(r.error, /unreadable|ENOENT/);
    });
    ok('exact quote passes and lands on disk', () => {
      const f = withReceipt({ title: 'goodq' });
      const r = rf.record(JSON.stringify(f));
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      const stored = JSON.parse(rows().find((l) => l.includes('"goodq"')));
      assert.deepStrictEqual(stored.evidence_quote, f.evidence_quote);
      assert.strictEqual(validateQuote(stored), null);
    });
    ok('diagnostics free-form field accepted, never validated', () => {
      const f = base({ title: 'diag', status: 'inconclusive', diagnostics: { whatever: { nested: [1, 2] }, junk: null } });
      const r = rf.record(JSON.stringify(f));
      assert.strictEqual(r.ok, true);
      assert.deepStrictEqual(JSON.parse(rows().at(-1)).diagnostics, f.diagnostics);
    });
  }

  // ─── gruppo 4: A3 hash-chain ───
  {
    fs.rmSync(FINDINGS, { force: true });
    rf.record(JSON.stringify(withReceipt({ title: 'c1' })));
    rf.record(JSON.stringify(withReceipt({ title: 'c2' })));
    rf.record(JSON.stringify(withReceipt({ title: 'c3' })));
    const rs = rows();
    const f1 = JSON.parse(rs[0]), f2 = JSON.parse(rs[1]);
    ok('genesis line anchors to 64 zeros, seq 1', () => {
      assert.strictEqual(f1.chain.seq, 1);
      assert.strictEqual(f1.chain.prev_sha256, '0'.repeat(64));
    });
    ok('second line chains to sha256(raw first line)', () => {
      assert.strictEqual(f2.chain.seq, 2);
      assert.strictEqual(f2.chain.prev_sha256, rf.sha256Hex(rs[0]));
    });
    ok('chain.ts stamped', () => assert.match(f2.chain.ts, /^\d{4}-\d{2}-\d{2}T/));

    // TAMPER: flip one byte in the MIDDLE line (its hash is referenced by line 3)
    const tampered = path.join(TMP, 'tampered.jsonl');
    const mid = rs.slice();
    assert.ok(mid[1].includes('"c2"'), 'fixture sanity');
    mid[1] = mid[1].replace('"title":"c2"', '"title":"d2"'); // single-byte semantic flip
    fs.writeFileSync(tampered, mid.join('\n') + '\n');
    ok('TAMPER: verifyFindingsChain detects flipped byte mid-chain', () => {
      const v = rf.verifyFindingsChain(fs.readFileSync(tampered, 'utf8').split('\n').filter(Boolean));
      assert.strictEqual(v.ok, false);
      assert.match(v.reason, /prev_sha256 mismatch/);
      assert.strictEqual(v.index, 2, 'break surfaces at the child of the tampered line');
    });
    ok('TAMPER: next record() refuses to append on broken chain', () => {
      const bak = process.env.FINDINGS_JSONL;
      process.env.FINDINGS_JSONL = tampered;
      try {
        const r = rf.record(JSON.stringify(withReceipt({ title: 'c4' })));
        assert.strictEqual(r.ok, false);
        assert.match(r.error, /hash-chain broken/);
        assert.strictEqual(fs.readFileSync(tampered, 'utf8').split('\n').filter(Boolean).length, 3, 'nothing appended');
      } finally { process.env.FINDINGS_JSONL = bak; }
    });

    ok('legacy unchained prefix is anchored, not failed', () => {
      const legacyFile = path.join(TMP, 'legacy.jsonl');
      const l1 = JSON.stringify({ severity: 'Low', title: 'old1', host: 'h1', poc: 'x', status: 'inconclusive' });
      const l2 = JSON.stringify({ severity: 'Low', title: 'old2', host: 'h2', poc: 'x', status: 'inconclusive' });
      fs.writeFileSync(legacyFile, l1 + '\n' + l2 + '\n');
      const bak = process.env.FINDINGS_JSONL;
      process.env.FINDINGS_JSONL = legacyFile;
      try {
        const r = rf.record(JSON.stringify(withReceipt({ title: 'first-chained' })));
        assert.strictEqual(r.ok, true, JSON.stringify(r));
        const lines = fs.readFileSync(legacyFile, 'utf8').split('\n').filter(Boolean);
        const third = JSON.parse(lines[2]);
        assert.strictEqual(third.chain.seq, 3, 'seq counts legacy lines too');
        assert.strictEqual(third.chain.prev_sha256, rf.sha256Hex(l2), 'anchored to last raw line');
        const v = rf.verifyFindingsChain(lines);
        assert.deepStrictEqual([v.ok, v.chained, v.legacy], [true, 1, 2]);
      } finally { process.env.FINDINGS_JSONL = bak; }
    });
    ok('unchained line AFTER a chained line = tampering', () => {
      const lines = rows(); // c1..c3 chained
      lines.push(JSON.stringify({ severity: 'Low', title: 'stripped', host: 'h', poc: 'x', status: 'inconclusive' }));
      const v = rf.verifyFindingsChain(lines);
      assert.strictEqual(v.ok, false);
      assert.match(v.reason, /interrupted/);
    });
    ok('tail tamper is absorbed by the chain (prev-hash limitation, documented)', () => {
      // A prev-hash chain cannot detect tampering of the TIP (no child references it yet);
      // mid-chain flips ARE detected (see above). Mitigation = external head anchoring.
      const openEnd = rows().slice();
      openEnd[2] = openEnd[2].replace('"title":"c3"', '"title":"x3"');
      const v = rf.verifyFindingsChain(openEnd);
      assert.strictEqual(v.ok, true, 'tip tampering is not self-revealing');
    });
    ok('dedup does not extend or break the chain', () => {
      const before = rows().length;
      const dup = withReceipt({ title: 'c1' }); // same dedup key as c1
      const r = rf.record(JSON.stringify(dup));
      assert.strictEqual(r.ok, true);
      assert.strictEqual(r.deduped, true);
      assert.strictEqual(rows().length, before, 'no new line appended');
    });
  }

  // ─── gruppo 5: recordWithVerify synthesizes mechanical receipts ───
  {
    fs.rmSync(FINDINGS, { force: true });
    const okRes = await rf.recordWithVerify(JSON.stringify(
      base({ title: 'rwv-ok', severity: 'Medium', verify: { url: 'https://target.example/x' } })),
      async () => ({ verified: true, runs: [{ ok: true }, { ok: true }], reason: '2/2 passed' }));
    ok('recordWithVerify success -> verified + disk-valid oracle+quote', () => {
      assert.strictEqual(okRes.ok, true, JSON.stringify(okRes));
      const stored = JSON.parse(rows().find((l) => l.includes('rwv-ok')));
      assert.strictEqual(stored.status, 'verified');
      assert.strictEqual(oracle.validateOracle(stored.oracle), null);
      assert.strictEqual(validateQuote(stored), null);
      assert.ok(fs.existsSync(path.join(TMP, stored.oracle.ref)), 'receipt artifact exists on disk');
    });
    const badRes = await rf.recordWithVerify(JSON.stringify(
      base({ title: 'rwv-bad', severity: 'Low', verify: { url: 'https://target.example/y' } })),
      async () => ({ verified: false, runs: [], reason: 'body missing "marker"' }));
    ok('recordWithVerify failure -> recorded with honest FAILED receipt', () => {
      assert.strictEqual(badRes.ok, true, JSON.stringify(badRes));
      const stored = JSON.parse(rows().find((l) => l.includes('rwv-bad')));
      assert.strictEqual(stored.status, 'confirmed'); // baseline behavior preserved
      assert.strictEqual(stored.verify_failed, true);
      assert.strictEqual(oracle.validateOracle(stored.oracle), null);
      assert.strictEqual(validateQuote(stored), null, 'anchor quote survives JSON-safe sanitization');
      const receipt = JSON.parse(fs.readFileSync(path.join(TMP, stored.oracle.ref), 'utf8'));
      assert.match(receipt.anchor, /outcome failed/);
    });
    ok('verify pipeline keeps chain intact end-to-end', () => {
      const v = rf.verifyFindingsChain(rows());
      assert.strictEqual(v.ok, true);
      assert.strictEqual(v.chained, rows().length);
    });

    // loot/redaction smoke (existing behavior preserved under the new gates)
    process.env.LOOT_JSONL = path.join(TMP, 'loot2.jsonl');
    ok('secret still vaulted to LOOT_JSONL', () => {
      const r = rf.record(JSON.stringify(base({ title: 'vault', status: 'inconclusive', secret: 'sk_live_abc123DEF456ghi789' })));
      assert.strictEqual(r.ok, true);
      const stored = JSON.parse(rows().find((l) => l.includes('"vault"')));
      assert.ok(stored.loot_id && stored.secret_fingerprint);
      const loot = fs.readFileSync(process.env.LOOT_JSONL, 'utf8').split('\n').filter(Boolean);
      assert.strictEqual(JSON.parse(loot.at(-1)).secret, 'sk_live_abc123DEF456ghi789');
    });
    ok('poc redaction still applied', () => {
      const r = rf.record(JSON.stringify(base({
        title: 'redact', status: 'inconclusive',
        poc: 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig',
      })));
      assert.strictEqual(r.ok, true);
      const stored = JSON.parse(rows().find((l) => l.includes('"redact"')));
      assert.match(stored.poc, /Bearer REDACTED/);
      assert.ok(!stored.poc.includes('eyJ'), 'JWT bytes gone');
    });
  }

  restoreEnvAndExit(fail ? 1 : 0);
})().catch((e) => { console.error(e); restoreEnvAndExit(1); });
