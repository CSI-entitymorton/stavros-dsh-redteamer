#!/usr/bin/env node
// Ondata 2 — SB2 test suite (B8 + D2 + E5 + E10 + budget hook su run.js).
// Offline & deterministica: fixture in mkdtemp, SCOPE_JSON/RUN_AUDIT_FILE/TOOL_REGISTRY/
// CACHE_DIR/BUDGET_* overrides; i "tool" di prova sono script sh locali che stampano stderr
// tipizzato — nessuna rete, nessun binario di scanning richiesto.
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
const RUN = path.join(WS, 'tools', 'run.js');
const TP = path.join(WS, 'tools', 'tool-plane.js');

function fakeTool(dir, name, stderrText, exitCode) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, `#!/bin/sh\ncat >&2 <<'MSG'\n${stderrText}\nMSG\nexit ${exitCode}\n`);
  fs.chmodSync(p, 0o755);
  return p;
}

async function main() {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'sb2-'));
  fs.mkdirSync(path.join(T, 'bin'), { recursive: true });
  const scopeFile = path.join(T, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({ targets: ['target.example'] }));
  const auditFile = path.join(T, 'audit.jsonl');

  // Fixture registry: echo read_only (cache-eligible), false NOT read_only,
  // zz-absent-bin registered with alternative curl (recovery injection).
  const regFile = path.join(T, 'registry.json');
  fs.writeFileSync(regFile, JSON.stringify({
    _comment: 'fixture',
    echo: { args_schema: '<text>', risk_tier: 'read', timeout_ms: 10000, rate_class: 'slow', alternative: null, read_only: true },
    false: { args_schema: '', risk_tier: 'active', timeout_ms: 10000, rate_class: 'slow', alternative: null, read_only: false },
    'zz-absent-bin': { args_schema: '<t>', risk_tier: 'read', timeout_ms: 10000, rate_class: 'slow', alternative: 'curl', read_only: true },
  }));

  function baseEnv(extra) {
    return Object.assign({}, process.env, {
      SCOPE_JSON: scopeFile,
      RUN_AUDIT_FILE: auditFile,
      TOOL_REGISTRY: regFile,
      CACHE_DIR: path.join(T, 'cache'),
    }, extra || {});
  }
  function resetAudit() { try { fs.unlinkSync(auditFile); } catch {} }
  function auditRows() {
    try { return fs.readFileSync(auditFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); }
    catch { return []; }
  }
  function lastAudit() { const r = auditRows(); return r[r.length - 1]; }

  console.log('SB2/B8: error taxonomy');
  ok('classifyFailure unit: tutte le 10 classi', () => {
    const m = require(RUN);
    assert.strictEqual(m.classifyFailure({ exitCode: 0 }), null);
    assert.strictEqual(m.classifyFailure({ exitCode: 1, timedOut: true }), 'timeout');
    assert.strictEqual(m.classifyFailure({ exitCode: 1, spawnError: 'spawn x ENOENT' }), 'tool_not_found');
    assert.strictEqual(m.classifyFailure({ exitCode: 2, text: 'HTTP 429 Too Many Requests, rate limit hit' }), 'rate_limited');
    assert.strictEqual(m.classifyFailure({ exitCode: 2, text: 'getaddrinfo ENOTFOUND target.example' }), 'dns_fail');
    assert.strictEqual(m.classifyFailure({ exitCode: 2, text: 'connect ECONNREFUSED 127.0.0.1:8080' }), 'conn_refused');
    assert.strictEqual(m.classifyFailure({ exitCode: 2, text: 'authentication failed for user admin' }), 'auth_failed');
    assert.strictEqual(m.classifyFailure({ exitCode: 2, text: 'parse error: invalid json near line 1' }), 'parse_fail');
    assert.strictEqual(m.classifyFailure({ exitCode: 7, text: '' }), 'unknown');
    // Ondata 3 E12 ha aggiunto la classe key_missing (gating TOOL_REQUIRES_KEY)
    assert.deepStrictEqual(Object.keys(m.ERROR_TAXONOMY).sort(),
      ['auth_failed', 'conn_refused', 'dns_fail', 'enforce_blocked', 'key_missing', 'parse_fail', 'rate_limited', 'scope_blocked', 'timeout', 'tool_not_found', 'unknown'].sort());
  });
  ok('taxonomyEntry: recovery action per classe (spec B8)', () => {
    const m = require(RUN);
    assert.strictEqual(m.taxonomyEntry('timeout').recovery.action, 'retry_backoff');
    assert.strictEqual(m.taxonomyEntry('scope_blocked').recovery.action, 'reduce_scope');
    assert.strictEqual(m.taxonomyEntry('enforce_blocked').recovery.action, 'escalate_operator');
    assert.strictEqual(m.taxonomyEntry(null).error_class, null);
  });

  function runCli(args, env) {
    return spawnSync('node', [RUN, ...args], { env, encoding: 'utf8', cwd: WS });
  }
  function runCliStdin(args, env, input) {
    return spawnSync('node', [RUN, ...args], { env, encoding: 'utf8', cwd: WS, input });
  }
  function reportOf(r) {
    const line = (r.stdout || '').split('\n').find((l) => l.startsWith('{"error_report"'));
    return line ? JSON.parse(line) : null;
  }

  await okAsync('functional: timeout class via --run-timeout + --error-report (host via stdin)', async () => {
    resetAudit();
    // Il target passa da STDIN (lista target del wrapper): `sleep` non accetta URL in argv.
    const r = runCliStdin(['--run-timeout', '250', '--error-report', 'sleep', '5'], baseEnv(), 'http://target.example/\n');
    assert.notStrictEqual(r.status, 0);
    const rep = reportOf(r);
    assert.ok(rep, 'error-report presente su stdout');
    assert.strictEqual(rep.error_class, 'timeout');
    assert.strictEqual(rep.recovery.action, 'retry_backoff');
    assert.strictEqual(lastAudit().timed_out, true);
    assert.strictEqual(lastAudit().error_class, 'timeout');
  });

  for (const [cls, txt, code] of [
    ['rate_limited', 'HTTP/1.1 429 Too Many Requests — rate limit exceeded, slow down', 2],
    ['dns_fail', 'getaddrinfo ENOTFAILED: Name or service not known (ENOTFOUND)', 2],
    ['conn_refused', 'connect ECONNREFUSED 127.0.0.1:8080', 2],
    ['auth_failed', 'authentication failed: access denied for user svc_scan', 1],
    ['parse_fail', 'parse error: invalid json token at byte 12', 3],
    ['unknown', 'segmentation-like generic crash output with no known signature', 7],
  ]) {
    await okAsync(`functional: ${cls} dal stderr del tool`, async () => {
      resetAudit();
      const bin = fakeTool(path.join(T, 'bin'), `fake-${cls}.sh`, txt, code);
      const r = await runCli(['--error-report', bin, 'http://target.example/'], baseEnv());
      const rep = reportOf(r);
      assert.ok(rep, `report mancante (stderr=${r.stderr && r.stderr.slice(0, 200)})`);
      assert.strictEqual(rep.error_class, cls, `stdout=${r.stdout}`);
      assert.strictEqual(lastAudit().error_class, cls);
    });
  }

  await okAsync('functional: tool_not_found con alternative_tool dalla registry', async () => {
    resetAudit();
    const r = await runCli(['--error-report', 'zz-absent-bin', 'http://target.example/'], baseEnv());
    const rep = reportOf(r);
    assert.ok(rep);
    assert.strictEqual(rep.error_class, 'tool_not_found');
    assert.match(rep.recovery.hint, /curl/);
  });

  await okAsync('functional: scope_blocked (host fuori scope) classificato', async () => {
    resetAudit();
    const r = await runCli(['echo', 'http://evil-host.example/'], baseEnv());
    assert.strictEqual(r.status, 1);
    const j = JSON.parse((r.stderr || '').split('\n').find((l) => l.startsWith('{')));
    assert.strictEqual(j.error_class, 'scope_blocked');
    assert.strictEqual(j.recovery.action, 'reduce_scope');
    assert.strictEqual(lastAudit().error_class, 'scope_blocked');
  });

  await okAsync('functional: enforce_blocked (nmap -p- senza rate) classificato, MAI bypass', async () => {
    resetAudit();
    const r = await runCli(['nmap', '-p-', 'http://target.example/'], baseEnv());
    assert.strictEqual(r.status, 1);
    const j = JSON.parse((r.stderr || '').split('\n').find((l) => l.startsWith('{')));
    assert.strictEqual(j.gate, 'enforce');
    assert.strictEqual(j.error_class, 'enforce_blocked');
    assert.strictEqual(j.recovery.action, 'escalate_operator');
    assert.strictEqual(lastAudit().gate, 'enforce');
  });

  console.log('SB2/D2: tool-registry');
  ok('validateRegistry: schema errato rilevato campo per campo', () => {
    const m = require(RUN);
    const errs = m.validateRegistry({ bad: { risk_tier: 'yolo', rate_class: 'turbo', read_only: 'yes', timeout_ms: -5, extra_field: 1 } });
    for (const frag of ['risk_tier', 'rate_class', 'read_only', 'timeout_ms', 'extra_field']) {
      assert.ok(errs.some((e) => e.includes(frag)), `manca ${frag} in ${JSON.stringify(errs)}`);
    }
    assert.deepStrictEqual(m.validateRegistry({ ok_bin: { risk_tier: 'read', rate_class: 'slow', read_only: true } }), []);
  });
  ok('loadRegistry: file assente -> loaded:false (fail-open documentato)', () => {
    const m = require(RUN);
    const reg = m.loadRegistry(path.join(T, 'nope.json'));
    assert.strictEqual(reg.loaded, false);
    assert.ok(reg.errors[0].includes('cannot read'));
  });
  await okAsync('CLI --registry-check: reale exit 0; corrotto/schema-errato exit≠0', async () => {
    const good = spawnSync('node', [RUN, '--registry-check'], { encoding: 'utf8', cwd: WS });
    assert.strictEqual(good.status, 0, good.stderr);
    assert.strictEqual(JSON.parse(good.stdout).ok, true);
    const badFile = path.join(T, 'bad-reg.json');
    fs.writeFileSync(badFile, '{not json');
    const bad = spawnSync('node', [RUN, '--registry-check', '--registry', badFile], { encoding: 'utf8', cwd: WS });
    assert.strictEqual(bad.status, 1);
    const schemaBad = path.join(T, 'schema-bad.json');
    fs.writeFileSync(schemaBad, JSON.stringify({ x: { risk_tier: 'nonsense', rate_class: 'slow', read_only: true } }));
    const sb = spawnSync('node', [RUN, '--registry-check', '--registry', schemaBad], { encoding: 'utf8', cwd: WS });
    assert.strictEqual(sb.status, 1);
    assert.match(sb.stdout, /risk_tier/);
  });
  await okAsync('warning non-bloccante per non-registrati; silenzio per registrati', async () => {
    resetAudit();
    const w = await runCli(['true', 'http://target.example/'], baseEnv()); // `true` ignora gli argomenti
    assert.strictEqual(w.status, 0, w.stderr);
    assert.match(w.stderr, /WARNING.*not registered/);
    assert.strictEqual(lastAudit().registry.registered, false);
    resetAudit();
    const q = await runCli(['echo', 'http://target.example/'], baseEnv());
    assert.strictEqual(q.status, 0);
    assert.doesNotMatch(q.stderr, /WARNING/);
    assert.strictEqual(lastAudit().registry.registered, true);
    assert.strictEqual(lastAudit().registry.risk_tier, 'read');
  });

  console.log('SB2/E10: cache opt-in');
  await okAsync('miss→store, hit=[cache-hit] SOLO per read_only:true', async () => {
    resetAudit();
    const r1 = await runCli(['--cache-ttl', '60', 'echo', 'http://target.example/cache-probe'], baseEnv());
    assert.strictEqual(r1.status, 0, r1.stderr);
    assert.strictEqual(lastAudit().cache_stored, true);
    assert.doesNotMatch(r1.stderr, /cache-hit/);
    const files = fs.readdirSync(path.join(T, 'cache'));
    assert.strictEqual(files.length, 1);
    resetAudit();
    const r2 = await runCli(['--cache-ttl', '60', 'echo', 'http://target.example/cache-probe'], baseEnv());
    assert.strictEqual(r2.status, 0);
    assert.match(r2.stderr, /\[cache-hit\]/);
    assert.strictEqual(r2.stdout.trim(), r1.stdout.trim(), 'output replayato identico');
    assert.strictEqual(lastAudit().cache_hit, true);
  });
  await okAsync('cache scaduta/corrotta → re-esecuzione (mai replay stantío)', async () => {
    const dir = path.join(T, 'cache');
    const f = path.join(dir, fs.readdirSync(dir)[0]);
    const obj = JSON.parse(fs.readFileSync(f, 'utf8'));
    obj.ts = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 min fa > ttl 60s
    fs.writeFileSync(f, JSON.stringify(obj));
    const r = await runCli(['--cache-ttl', '60', 'echo', 'http://target.example/cache-probe'], baseEnv());
    assert.strictEqual(r.status, 0);
    assert.doesNotMatch(r.stderr, /cache-hit/);
    fs.writeFileSync(f, '{corrupt json');
    const r2 = await runCli(['--cache-ttl', '60', 'echo', 'http://target.example/cache-probe'], baseEnv());
    assert.strictEqual(r2.status, 0);
    JSON.parse(fs.readFileSync(f, 'utf8')); // riscritto valido
  });
  await okAsync('avversariale: scanner attivo e read_only:false MAI cacheabili', async () => {
    const before = fs.readdirSync(path.join(T, 'cache')).length;
    const r1 = await runCli(['--cache-ttl', '60', 'false', 'http://target.example/'], baseEnv());
    assert.strictEqual(r1.status, 1);
    assert.match(r1.stderr, /cache refused.*read_only=false/);
    const r2 = await runCli(['--cache-ttl', '60', '--run-timeout', '150', 'nmap', '-sn', 'http://target.example/'], baseEnv());
    assert.match(r2.stderr, /cache refused/);
    assert.strictEqual(fs.readdirSync(path.join(T, 'cache')).length, before, 'nessun nuovo file cache');
  });

  console.log('SB2/budget hook: pre-exec exit 3/4 bloccano');
  await okAsync('engagement halt -> exit 3, child NON eseguito', async () => {
    const cfgF = path.join(T, 'budget.json');
    fs.writeFileSync(cfgF, JSON.stringify({ max_requests: 1 }));
    const stateF = path.join(T, 'op-state.json');
    const audF = path.join(T, 'b-audit.jsonl');
    fs.writeFileSync(audF, '{"ts":"a"}\n{"ts":"b"}\n'); // 2 righe > cap 1
    const marker = path.join(T, 'child-ran.marker');
    const env = baseEnv({
      BUDGET_CONFIG_FILE: cfgF, BUDGET_STATE_FILE: stateF, RUN_AUDIT_FILE: audF,
    });
    delete env.AGENT_CLASS;
    const r = spawnSync('node', [RUN, '--run-timeout', '3000', 'bash', '-c', `touch ${marker}; echo http://target.example/`], { env, encoding: 'utf8', cwd: WS });
    assert.strictEqual(r.status, 3, `exit=${r.status} stderr=${r.stderr}`);
    assert.match(r.stderr, /OPERATOR REQUEST REQUIRED/);
    assert.strictEqual(fs.existsSync(marker), false, 'il child NON deve essere eseguito');
    // l'audit row del run.js registra il blocco budget
    const rows = fs.readFileSync(audF, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const blk = rows.filter((x) => x.budget_blocked);
    assert.strictEqual(blk.length, 1);
    assert.strictEqual(blk[0].budget_exit, 3);
  });
  await okAsync('classe agente in halt -> exit 4 (AGENT_CLASS inoltrata)', async () => {
    // NB: serve un engagement config VALIDO (misconfig = check disabilitato fail-open);
    // il cap engagement resta sotto soglia così il blocco arriva dalla CLASSE (exit 4).
    const cfgF = path.join(T, 'budget-eng-ok.json');
    fs.writeFileSync(cfgF, JSON.stringify({ max_requests: 100000 }));
    const classesF = path.join(T, 'budgets.json');
    fs.writeFileSync(classesF, JSON.stringify({ classes: { limited: { max_tool_calls: 2 } } }));
    const cDir = path.join(T, 'counters');
    fs.mkdirSync(cDir, { recursive: true });
    fs.writeFileSync(path.join(cDir, 'tool-calls-limited.jsonl'), '{"ts":1}\n{"ts":2}\n{"ts":3}\n'); // 3 > cap 2
    const engAudF = path.join(T, 'eng-audit.jsonl'); // contatore engagement: vuoto -> sotto cap
    fs.writeFileSync(engAudF, '');
    const env = baseEnv({
      BUDGET_CONFIG_FILE: cfgF, BUDGET_STATE_FILE: path.join(T, 'st4.json'),
      BUDGET_CLASSES_FILE: classesF, BUDGET_COUNTERS_DIR: cDir, AGENT_CLASS: 'limited',
      RUN_AUDIT_FILE: engAudF,
    });
    const marker = path.join(T, 'child-ran-4.marker');
    const r = spawnSync('node', [RUN, 'bash', '-c', `touch ${marker}; echo http://target.example/`], { env, encoding: 'utf8', cwd: WS });
    assert.strictEqual(r.status, 4, `exit=${r.status} stderr=${r.stderr}`);
    assert.strictEqual(fs.existsSync(marker), false);
  });
  await okAsync('sotto soglia -> esecuzione normale + tick opzionale registrato', async () => {
    const cfgF = path.join(T, 'budget-ok.json');
    fs.writeFileSync(cfgF, JSON.stringify({ max_requests: 100 }));
    const classesF = path.join(T, 'budgets-ok.json');
    fs.writeFileSync(classesF, JSON.stringify({ classes: { limited: { max_tool_calls: 100 } } }));
    const cDir = path.join(T, 'counters-ok');
    fs.mkdirSync(cDir, { recursive: true });
    const audF = path.join(T, 'ok-audit.jsonl');
    fs.writeFileSync(audF, '');
    const env = baseEnv({
      BUDGET_CONFIG_FILE: cfgF, BUDGET_STATE_FILE: path.join(T, 'st-ok.json'),
      BUDGET_CLASSES_FILE: classesF, BUDGET_COUNTERS_DIR: cDir,
      AGENT_CLASS: 'limited', RUNJS_BUDGET_TICK_CLASS: 'limited', RUN_AUDIT_FILE: audF,
    });
    const r = await runCli(['echo', 'http://target.example/tick'], env);
    assert.strictEqual(r.status, 0, r.stderr);
    const cFile = path.join(cDir, 'tool-calls-limited.jsonl');
    assert.strictEqual(fs.readFileSync(cFile, 'utf8').split('\n').filter(Boolean).length, 1, 'tick producer ha registrato 1 chiamata');
  });

  console.log('SB2/E5: tool-plane --require preflight');
  ok('requireCheck unit + CLI E2E con TOOL_PLANE_CONFIG', () => {
    const m = require(TP);
    const data = { ts: 'x', tools: {
      'zz-miss-req': { category: 'recon', required: true, installed: false },
      'zz-miss-opt': { category: 'recon', required: false, installed: false },
      bash: { category: 'scan', required: false, installed: true },
    } };
    const req = m.requireCheck(data, 'recon,scan', null);
    assert.strictEqual(req.ok, false);
    assert.deepStrictEqual(req.missing.map((x) => x.bin), ['zz-miss-req']);
    assert.deepStrictEqual(req.optional_missing.map((x) => x.bin), ['zz-miss-opt']);
    const allPresent = m.requireCheck({ ts: 'x', tools: { bash: { category: 'scan', required: false, installed: true } } }, 'scan', null);
    assert.strictEqual(allPresent.ok, true);
  });
  await okAsync('CLI: required mancante -> exit≠0 elencando; opzionali -> exit 0', async () => {
    const planeCfg = path.join(T, 'plane.json');
    // NB: la categoria 'lab' NON esiste nella mappa built-in (recon/scan/web/...): cosí il test
    // resta hermetico anche su runner puliti dove nmap e soci non sono installati (CI).
    fs.writeFileSync(planeCfg, JSON.stringify({
      recon: { 'zz-missing-required-x': { required: true }, 'zz-missing-optional-x': { required: false } },
      lab: { bash: { required: false }, 'zz-missing-optional-y': { required: false } },
    }));
    const outF = path.join(T, 'tp-out.json');
    const env = Object.assign({}, process.env, { TOOL_PLANE_CONFIG: planeCfg, TOOL_PLANE_OUT: outF });
    const bad = spawnSync('node', [TP, '--json', '--require', 'recon'], { env, encoding: 'utf8' });
    assert.strictEqual(bad.status, 1, bad.stdout);
    const jb = JSON.parse(bad.stdout);
    assert.strictEqual(jb.ok, false);
    assert.ok(jb.missing.some((m) => m.bin === 'zz-missing-required-x'));
    const good = spawnSync('node', [TP, '--json', '--require', 'lab'], { env, encoding: 'utf8' });
    assert.strictEqual(good.status, 0, good.stdout);
    const jg = JSON.parse(good.stdout);
    assert.strictEqual(jg.ok, true);
    assert.ok(jg.optional_missing.length <= 1);
  });
  await okAsync('CLI: --require-bin su bin sconosciuto alla mappa -> verifica live', async () => {
    const planeCfg = path.join(T, 'plane-empty.json');
    fs.writeFileSync(planeCfg, JSON.stringify({}));
    const outF = path.join(T, 'tp-out2.json');
    const env = Object.assign({}, process.env, { TOOL_PLANE_CONFIG: planeCfg, TOOL_PLANE_OUT: outF });
    const miss = spawnSync('node', [TP, '--json', '--require-bin', 'bash,zz-fake-absent-tool'], { env, encoding: 'utf8' });
    assert.strictEqual(miss.status, 1);
    const jm = JSON.parse(miss.stdout);
    assert.ok(jm.missing.some((m) => m.bin === 'zz-fake-absent-tool'));
    const present = spawnSync('node', [TP, '--json', '--require-bin', 'bash'], { env, encoding: 'utf8' });
    assert.strictEqual(present.status, 0);
  });

  // pulizia
  try { fs.rmSync(T, { recursive: true, force: true }); } catch {}

  console.log(`\nsb2: ${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
