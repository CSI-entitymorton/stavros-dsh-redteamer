#!/usr/bin/env node
// Ondata 2 — SB1 test suite (C1w + E7): tools/workflow.js functional + adversarial.
// Offline & deterministic: fixtures in mkdtemp, SCOPE_JSON/EVIDENCE/COVERAGE/LOG overrides,
// steps only via `node tools/run.js echo|false` (always present, no network).
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
const WF = path.join(WS, 'tools', 'workflow.js');

function tmpCtx() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-test-'));
  const scopeFile = path.join(dir, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({ targets: ['target.example', '127.0.0.1'] }));
  const env = Object.assign({}, process.env, {
    SCOPE_JSON: scopeFile,
    WORKFLOW_LOG_DIR: path.join(dir, 'logs'),
    EVIDENCE_INDEX_FILE: path.join(dir, 'evidence-index.md'),
    COVERAGE_WORKFLOW_FILE: path.join(dir, 'coverage-workflow.json'),
  });
  delete env.STAVROS_PRIVACY;
  return { dir, scopeFile, env };
}

function runWf(args, env) {
  return spawnSync('node', [WF, ...args], { env, encoding: 'utf8', cwd: WS });
}
// runWfIn: same but with a scratch cwd (artifacts paths resolve against process.cwd())
function runWfIn(args, env, cwd) {
  return spawnSync('node', [WF, ...args], { env, encoding: 'utf8', cwd });
}

const FIXTURE = `name: wf-fixture
description: fixture per test offline
vars:
  fname: art.txt
requires:
  - echo
steps:
  - id: s1-echo
    cmd: node tools/run.js echo http://{target}/probe
    artifacts:
      - path: "{fname}"
        surface: demo
  - id: s2-fail-continue
    cmd: node tools/run.js false http://{target}/x
    on_error: continue
  - id: s3-only-after-zero
    cmd: node tools/run.js echo after-zero {target}
    when:
      exit_code: 0
  - id: s4-final
    cmd: node tools/run.js echo final {target}
`;

const FIXTURE_STOP = `name: wf-stop
requires:
  - echo
steps:
  - id: a-ok
    cmd: node tools/run.js echo one {target}
  - id: b-fail
    cmd: node tools/run.js false {target}
  - id: c-never
    cmd: node tools/run.js echo never {target}
`;

const FIXTURE_PARALLEL = `name: wf-par
requires:
  - echo
steps:
  - id: p1
    cmd: node tools/run.js echo par-one {target}
    parallel_group: g
  - id: p2
    cmd: node tools/run.js echo par-two {target}
    parallel_group: g
  - id: after
    cmd: node tools/run.js echo after {target}
`;

(async () => {
  console.log('workflow: functional');
  const seeds = ['recon-baseline.yaml', 'enum-http.yaml', 'enum-smb.yaml', 'enum-ldap.yaml'];
  for (const s of seeds) {
    ok(`validate seed ${s}`, () => {
      const r = runWf(['validate', path.join(WS, 'workflows', s)], process.env);
      assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
      const j = JSON.parse(r.stdout);
      assert.strictEqual(j.ok, true);
      assert.ok(j.steps >= 2);
    });
  }

  const ctx = tmpCtx();
  const fx = path.join(ctx.dir, 'fixture.yaml');
  fs.writeFileSync(fx, FIXTURE);

  // E7: dry-run prints execution-plan and executes/writes NOTHING
  const evBefore = fs.existsSync(ctx.env.EVIDENCE_INDEX_FILE);
  let planOut = '';
  await okAsync('E7 dry-run prints execution_plan, writes nothing', async () => {
    const r = runWf(['run', fx, '-t', 'target.example', '--dry-run'], ctx.env);
    assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
    planOut = r.stdout;
    const j = JSON.parse(r.stdout);
    assert.strictEqual(j.execution_plan, true);
    assert.strictEqual(j.target_scope.ok, true, JSON.stringify(j.target_scope));
    assert.strictEqual(j.waves.length, 4); // sequential steps: one explicit wave per step
    assert.strictEqual(j.missing_requires.length, 0);
    assert.strictEqual(fs.existsSync(ctx.env.WORKFLOW_LOG_DIR), false, 'no log dir on dry-run');
    assert.strictEqual(fs.existsSync(ctx.env.EVIDENCE_INDEX_FILE), evBefore, 'evidence untouched on dry-run');
    assert.strictEqual(fs.existsSync(ctx.env.COVERAGE_WORKFLOW_FILE), false, 'coverage untouched on dry-run');
  });

  await okAsync('functional e2e: when-gating, on_error continue, artifacts+evidence+coverage', async () => {
    // NB: il dialetto richiede cmd "node tools/run.js …" → cwd DEVE essere la root del
    // workspace (dove vivono tools/ e reports/); gli artifact relativi si risolvono lì.
    const r = runWf(['run', fx, '-t', 'target.example'], ctx.env);
    const j = r.status === 0 ? null : r.stderr;
    assert.strictEqual(r.status, 0, `exit=${r.status} err=${j}`);
    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.ok, true);
    const byId = {};
    for (const s of out.steps) byId[s.id] = s;
    assert.strictEqual(byId['s1-echo'].exit, 0);
    assert.strictEqual(byId['s1-echo'].artifacts[0].path, 'art.txt');
    assert.strictEqual(byId['s2-fail-continue'].exit, 1);
    assert.strictEqual(byId['s3-only-after-zero'].skipped, 'when.exit_code', 'lastExit was 1 → skip');
    assert.strictEqual(byId['s4-final'].exit, 0);
    // log jsonl exists with machine-readable lines
    const logs = fs.readdirSync(ctx.env.WORKFLOW_LOG_DIR).filter((f) => f.startsWith('wf-fixture-'));
    assert.strictEqual(logs.length, 1);
    const lines = fs.readFileSync(path.join(ctx.env.WORKFLOW_LOG_DIR, logs[0]), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    assert.ok(lines.some((l) => l.event === 'run_start'));
    const stepLines = lines.filter((l) => l.event === 'step');
    assert.strictEqual(stepLines.length, 3, '3 executed steps logged');
    assert.ok(stepLines.every((l) => typeof l.exit === 'number' && Array.isArray(l.args)), 'loop-watch compatible bin/args fields');
    assert.ok(lines.some((l) => l.event === 'run_summary' && l.ok === true));
    // coverage-workflow.json updated
    const cov = JSON.parse(fs.readFileSync(ctx.env.COVERAGE_WORKFLOW_FILE, 'utf8'));
    assert.strictEqual(cov.workflows['wf-fixture'].steps.length, 4);
    assert.deepStrictEqual(cov.workflows['wf-fixture'].targets, ['target.example']);
    // evidence-index rows appended ONLY for existing artifacts (art.txt does not exist yet);
    // with zero existing artifacts the file may not even be created yet.
    const ev = fs.existsSync(ctx.env.EVIDENCE_INDEX_FILE) ? fs.readFileSync(ctx.env.EVIDENCE_INDEX_FILE, 'utf8') : '';
    assert.ok(!ev.includes('art.txt'), 'non-existent artifact not registered');
    // create the artifact in the workspace root (artifact paths resolve against cwd) → re-run only s1 → evidence row appended
    const wsArt = path.join(WS, 'art.txt');
    fs.writeFileSync(wsArt, 'demo-artifact\n');
    try {
      const r2 = runWf(['run', fx, '-t', 'target.example', '--only-step', 's1-echo'], ctx.env);
      assert.strictEqual(r2.status, 0, r2.stderr);
      const ev2 = fs.readFileSync(ctx.env.EVIDENCE_INDEX_FILE, 'utf8');
      assert.ok(ev2.includes('| `art.txt` |'), 'artifact registered in evidence-index');
      assert.match(ev2, /workflow `wf-fixture` step `s1-echo` artefatto prodotto \(surface: demo; exit 0\)/);
    } finally {
      if (fs.existsSync(wsArt)) fs.unlinkSync(wsArt); // no residue in workspace root
    }
  });

  await okAsync('on_error stop (default): abort + exit code propagated', async () => {
    const f2 = path.join(ctx.dir, 'stop.yaml');
    fs.writeFileSync(f2, FIXTURE_STOP);
    const r = runWf(['run', f2, '-t', 'target.example'], ctx.env);
    assert.strictEqual(r.status, 1, `expected exit 1, got ${r.status}`);
    const out = JSON.parse(r.stdout);
    const byId = {};
    for (const s of out.steps) byId[s.id] = s;
    assert.strictEqual(byId['a-ok'].exit, 0);
    assert.strictEqual(byId['b-fail'].exit, 1);
    assert.strictEqual(byId['c-never'].skipped, 'aborted');
    assert.strictEqual(out.summary.failed_step, 'b-fail');
  });

  await okAsync('parallel_group: same-label consecutive steps in one wave', async () => {
    const f3 = path.join(ctx.dir, 'par.yaml');
    fs.writeFileSync(f3, FIXTURE_PARALLEL);
    const d = runWf(['run', f3, '-t', 'target.example', '--dry-run'], ctx.env);
    assert.strictEqual(d.status, 0, d.stderr);
    const plan = JSON.parse(d.stdout);
    assert.strictEqual(plan.waves.length, 2, 'wave1=[p1,p2] wave2=[after]');
    assert.strictEqual(plan.waves[0].parallel, true);
    assert.strictEqual(plan.waves[0].group, 'g');
    const r = runWf(['run', f3, '-t', 'target.example'], ctx.env);
    assert.strictEqual(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.deepStrictEqual(out.steps.map((s) => s.id), ['p1', 'p2', 'after']);
    assert.ok(out.steps.every((s) => s.exit === 0));
  });

  await okAsync('--only-step unknown id -> usage error 2', async () => {
    const r = runWf(['run', fx, '-t', 'target.example', '--only-step', 'nope'], ctx.env);
    assert.strictEqual(r.status, 2, `stderr=${r.stderr}`);
  });

  await okAsync('missing -t -> usage error', async () => {
    const r = runWf(['run', fx], ctx.env);
    assert.strictEqual(r.status, 2);
  });

  console.log('workflow: preflight (aggancio E5) & scope fail-closed');
  await okAsync('missing required binary -> preflight fail chiaro', async () => {
    const f4 = path.join(ctx.dir, 'req.yaml');
    fs.writeFileSync(f4, `name: wf-req\nrequires:\n  - definitely-not-installed-bin-xz\nsteps:\n  - id: x\n    cmd: node tools/run.js echo hi {target}\n`);
    const r = runWf(['run', f4, '-t', 'target.example'], ctx.env);
    assert.notStrictEqual(r.status, 0);
    const e = JSON.parse(r.stderr.split('\n').find((l) => l.startsWith('{')));
    assert.strictEqual(e.error, 'preflight-failed');
    assert.deepStrictEqual(e.missing_requires, ['definitely-not-installed-bin-xz']);
  });

  await okAsync('out-of-scope target blocked anche in dry-run', async () => {
    const logsBefore = fs.existsSync(ctx.env.WORKFLOW_LOG_DIR) ? fs.readdirSync(ctx.env.WORKFLOW_LOG_DIR).sort() : [];
    const r = runWf(['run', fx, '-t', 'evil.example', '--dry-run'], ctx.env);
    assert.strictEqual(r.status, 1);
    const e = JSON.parse(r.stderr.split('\n').find((l) => l.startsWith('{')));
    assert.strictEqual(e.error, 'preflight-failed');
    assert.strictEqual(e.target_scope.ok, false);
    const logsAfter = fs.existsSync(ctx.env.WORKFLOW_LOG_DIR) ? fs.readdirSync(ctx.env.WORKFLOW_LOG_DIR).sort() : [];
    assert.deepStrictEqual(logsAfter, logsBefore, 'dry-run bloccato: nessun log scritto');
  });

  await okAsync('unresolved placeholder fail-closed (mai riga comando parziale)', async () => {
    const f5 = path.join(ctx.dir, 'ph.yaml');
    fs.writeFileSync(f5, `name: wf-ph\nrequires:\n  - echo\nsteps:\n  - id: x\n    cmd: node tools/run.js echo {nope} {target}\n`);
    const r = runWf(['run', f5, '-t', 'target.example'], ctx.env);
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /unresolved placeholder \{nope\}/);
  });

  console.log('workflow: dialect validation avversariale');
  ok('cmd senza prefisso node tools/run.js -> reject', () => {
    const m = require(WF.replace(/\.js$/, ''));
    const errs = m.validateDoc({ name: 'bad', steps: [{ id: 'x', cmd: 'nmap -sn t' }] });
    assert.ok(errs.some((e) => /MUST start with/.test(e)));
  });
  ok('duplicate step ids -> reject', () => {
    const m = require(WF.replace(/\.js$/, ''));
    const errs = m.validateDoc({ name: 'bad', steps: [
      { id: 'x', cmd: 'node tools/run.js echo a' }, { id: 'x', cmd: 'node tools/run.js echo b' },
    ] });
    assert.ok(errs.some((e) => /duplicate/.test(e)));
  });
  ok('on_error valore illegale -> reject', () => {
    const m = require(WF.replace(/\.js$/, ''));
    const errs = m.validateDoc({ name: 'bad', steps: [{ id: 'x', cmd: 'node tools/run.js echo a', on_error: 'ignore' }] });
    assert.ok(errs.some((e) => /stop\|continue/.test(e)));
  });

  console.log('workflow: mini-parser parity & loud failures');
  await okAsync('WORKFLOW_NO_PYYAML=1: stesso piano del path PyYAML (parity)', async () => {
    const envMini = Object.assign({}, ctx.env, { WORKFLOW_NO_PYYAML: '1' });
    const v = runWf(['validate', fx], envMini);
    assert.strictEqual(v.status, 0, v.stderr);
    assert.strictEqual(JSON.parse(v.stdout).parser, 'mini');
    const d = runWf(['run', fx, '-t', 'target.example', '--dry-run'], envMini);
    assert.strictEqual(d.status, 0, d.stderr);
    assert.strictEqual(d.stdout, planOut, 'mini-parser produce lo STESSO execution-plan di PyYAML');
  });
  await okAsync('mini-parser: flow-syntax inline rifiutata ad alta voce (niente guess)', async () => {
    const f6 = path.join(ctx.dir, 'flow.yaml');
    fs.writeFileSync(f6, 'name: flow-bad\nrequires: [nmap]\nsteps:\n  - id: x\n    cmd: node tools/run.js echo {target}\n');
    const envMini = Object.assign({}, ctx.env, { WORKFLOW_NO_PYYAML: '1' });
    const r = runWf(['validate', f6], envMini);
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /yaml-parse-failed.*(uses inline\/flow syntax|unsupported syntax)/);
  });
  await okAsync('YAML malformato (tab) -> parse fallito con riga citata', async () => {
    const f7 = path.join(ctx.dir, 'tab.yaml');
    fs.writeFileSync(f7, 'name: tab-bad\nsteps:\n\t- id: x\n');
    const envMini = Object.assign({}, ctx.env, { WORKFLOW_NO_PYYAML: '1' });
    const r = runWf(['validate', f7], envMini);
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /yaml-parse-failed/);
  });

  console.log(`workflow: ${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
