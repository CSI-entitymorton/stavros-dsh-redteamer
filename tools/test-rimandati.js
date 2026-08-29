#!/usr/bin/env node
// Suite per gli item rimandati APPLICATI (batch operator-approvato, benchmark E1/E2 esclusi):
//   A4 : egress-proxy allowlist (deny-by-default) + run.js HTTP_PROXY injection
//   E6 : decision.conditions nel dialetto workflow (WAF → rate ridotto, in YAML)
//   E8 : kind RECOVER (ricostruzione dagli artefatti, niente replay)
//   E9 : process registry (task-id/pause/resume/terminate senza kill, hook run.js)
//   E4 : fleet dichiarativa agents.yml (plan zero-writes, render deterministico, apply --yes)
//   E13: continuation-advice (ultime N voci → consiglio deterministico)
//   F9 : patch del piano a caldo (overlay step, fail-closed su id inesistente)
//   E11: MCP inverso (bridge JSON-RPC stdio che espone SOLO tool guardati)
// Tutto OFFLINE (solo stdlib), fixture SOLO in mkdtemp, env override, MAI path reali.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
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
const cli = (file, args, env) => spawnSync(process.execPath, [file, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 30000 });
const waitFor = (fn, ms) => new Promise((resolve, reject) => {
  const t0 = Date.now();
  const iv = setInterval(() => {
    if (fn()) { clearInterval(iv); resolve(); }
    else if (Date.now() - t0 > ms) { clearInterval(iv); reject(new Error('timeout waiting for condition')); }
  }, 50);
});

function whenListening(server) {
  return new Promise((resolve) => {
    if (server.address()) return resolve();
    const t = setInterval(() => { if (server.address()) { clearInterval(t); resolve(); } }, 25);
    server.once('listening', () => { clearInterval(t); resolve(); });
  });
}

async function main() {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'rimandati-'));
  const SCOPE = path.join(T, 'scope.json');
  fs.writeFileSync(SCOPE, JSON.stringify({ targets: ['target.example'], exclusions: [] }));

  // ================================================================ A4 egress-proxy
  console.log('A4 — egress-proxy allowlist');
  {
    const { serve, STATE } = require(path.join(WS, 'tools', 'egress-proxy'));
    const scopePath = path.join(T, 'egr-scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({ allowed_ips: ['127.0.0.1'] }));
    const auditPath = path.join(T, 'egr-audit.jsonl');
    // serve() legge SCOPE_JSON a startup e EGRESS_AUDIT a ogni audit: applico l'env PRIMA.
    const SAVED_EGR = { SCOPE_JSON: process.env.SCOPE_JSON, EGRESS_AUDIT: process.env.EGRESS_AUDIT };
    process.env.SCOPE_JSON = scopePath;
    process.env.EGRESS_AUDIT = auditPath;
    const origin = http.createServer((rq, rs) => rs.end('origin-ok')).listen(0, '127.0.0.1');
    await whenListening(origin);
    const originPort = origin.address().port;
    const proxy = serve(0);
    await whenListening(proxy);
    const proxyPort = proxy.address().port;
    const proxyGet = (absUrl) => new Promise((resolve) => {
      const u = new URL(absUrl);
      const req = http.request({ host: '127.0.0.1', port: proxyPort, method: 'GET', path: absUrl, headers: { host: u.host }, agent: false },
        (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode, body: b })); });
      req.on('error', () => resolve({ status: 0 }));
      req.end();
    });
    // Sequenziale: ogni asserzione async è attesa PRIMA della successiva (okn = ok+await).
    const okn = async (name, fn) => { try { await fn(); pass++; console.log(`  PASS ${name}`); } catch (e) { fail++; console.log(`  FAIL ${name}: ${e.message}`); } };
    await okn('in-scope (127.0.0.1) forwarded → 200', async () => {
      const r = await proxyGet(`http://127.0.0.1:${originPort}/x`);
      assert.strictEqual(r.status, 200, 'status ' + r.status);
      assert.strictEqual(r.body, 'origin-ok');
    });
    await okn('out-of-scope host → 403 deny-by-default', async () => {
      const r = await proxyGet('http://10.9.9.9/x');
      assert.strictEqual(r.status, 403, 'status ' + r.status);
    });
    await okn('audit registra allow E deny', () => {
      const audit = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
      assert.ok(audit.some((a) => a.verdict === 'allow'));
      assert.ok(audit.some((a) => a.verdict === 'deny'));
    });
    await okn('run.js inietta HTTP_PROXY quando lo state del proxy è attivo', () => {
      fs.mkdirSync(path.dirname(STATE), { recursive: true });
      fs.writeFileSync(STATE, JSON.stringify({ pid: process.pid, port: 9098 }));
      const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'run.js'), 'node', '-e', 'process.stdout.write(process.env.HTTP_PROXY||"none")', '127.0.0.1'],
        { cwd: WS, env: { ...process.env, SCOPE_JSON: scopePath }, encoding: 'utf8' });
      assert.ok(r.stdout.includes('http://127.0.0.1:9098'), r.stdout);
      fs.rmSync(STATE, { force: true });
    });
    proxy.close(); origin.close();
    for (const [k, v] of Object.entries(SAVED_EGR)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }

  // ================================================================ E6 decision.conditions
  console.log('E6 — decision.conditions nel workflow');
  {
    const wfFile = path.join(T, 'wf-e6.yaml');
    const wafFile = path.join(T, 'waf.txt');
    fs.writeFileSync(wafFile, 'WAF detected: 403\n');
    fs.writeFileSync(wfFile, `name: wf-e6
steps:
  - id: scan
    cmd: node tools/run.js nmap --rate {rate} {target}
decisions:
  - id: waf-rate
    when:
      file_contains:
        path: ${wafFile}
        text: "WAF"
    then:
      set_var:
        name: rate
        value: slow
`);
    ok('validate con decisions → ok (pyyaml)', () => {
      const r = cli(path.join(WS, 'tools', 'workflow.js'), ['validate', wfFile]);
      assert.strictEqual(r.status, 0, r.stderr);
    });
    ok('dry-run applica la decisione: {rate} → slow (WAF nel file probe)', () => {
      const r = cli(path.join(WS, 'tools', 'workflow.js'), ['run', wfFile, '-t', 'target.example', '--dry-run'], { SCOPE_JSON: SCOPE });
      const d = JSON.parse(r.stdout);
      assert.deepStrictEqual(d.decisions_applied.map((x) => x.id), ['waf-rate']);
      const cmd = d.waves.flatMap((w) => w.steps).find((s) => s.id === 'scan').cmd;
      assert.ok(cmd.includes('--rate slow'), cmd);
    });
    ok('decisione env: WAF_DETECTED=1 → rate slow; assente → default (normal)', () => {
      const f2 = path.join(T, 'wf-e6-env.yaml');
      fs.writeFileSync(f2, `name: wf-e6-env
vars:
  rate: normal
steps:
  - id: scan
    cmd: node tools/run.js nmap {rate} {target}
decisions:
  - id: env-rate
    when:
      env:
        name: WAF_DETECTED
        equals: "1"
    then:
      set_var:
        name: rate
        value: slow
`);
      const WFRUN = path.join(WS, 'tools', 'workflow.js');
      let r = cli(WFRUN, ['run', f2, '-t', 'target.example', '--dry-run'], { SCOPE_JSON: SCOPE, WAF_DETECTED: '1' });
      assert.strictEqual(r.status, 0, r.stderr);
      let d = JSON.parse(r.stdout);
      assert.strictEqual(d.decisions_applied.length, 1);
      let cmd = d.waves.flatMap((w) => w.steps).find((s) => s.id === 'scan').cmd;
      assert.ok(cmd.includes(' slow '), cmd);
      r = cli(WFRUN, ['run', f2, '-t', 'target.example', '--dry-run'], { SCOPE_JSON: SCOPE });
      assert.strictEqual(r.status, 0, r.stderr);
      d = JSON.parse(r.stdout);
      assert.strictEqual(d.decisions_applied.length, 0);
      cmd = d.waves.flatMap((w) => w.steps).find((s) => s.id === 'scan').cmd;
      assert.ok(cmd.includes(' normal '), cmd);
    });
    ok('evaluateDecisions: funzione pura (input non mutato)', () => {
      const wfLib = require(path.join(WS, 'tools', 'workflow'));
      const doc = { decisions: [{ id: 'd', when: { env: { name: '__E6_UNSET_VAR__', equals: 'x' } }, then: { set_var: { name: 'r', value: 'slow' } } }] };
      const before = JSON.stringify(doc);
      const r = wfLib.evaluateDecisions(doc, {});
      assert.strictEqual(r.applied.length, 0);
      assert.strictEqual(JSON.stringify(doc), before);
    });
  }

  // ================================================================ E8 recover
  console.log('E8 — kind RECOVER');
  {
    const REC = path.join(WS, 'tools', 'recover.js');
    const audit = path.join(T, 'audit-dead.jsonl');
    fs.writeFileSync(audit, [
      JSON.stringify({ ts: '2026-08-26T10:00:00Z', bin: 'nmap', ok: true, exit: 0 }),
      JSON.stringify({ ts: '2026-08-26T10:01:00Z', bin: 'nuclei', blocked: true, error_class: 'scope_blocked', reason: 'out-of-scope host(s)' }),
      JSON.stringify({ ts: '2026-08-26T10:02:00Z', bin: 'nuclei', blocked: true, error_class: 'scope_blocked', reason: 'out-of-scope host(s)' }),
    ].join('\n') + '\n');
    const opFile = path.join(T, 'op.json');
    fs.writeFileSync(opFile, JSON.stringify({ revision: 1, transitions: [{ ts: '2026-08-26T09:00:00Z' }], leases: {} }));
    ok('turno morto rilevato (ultima invocazione bloccata, nessun progresso) → exit 1', () => {
      const r = cli(REC, ['plan', '--audit', audit, '--state', opFile, '--logdir', path.join(T, 'nologs'), '--findings', path.join(T, 'nf.jsonl'), '--tail', '3']);
      assert.strictEqual(r.status, 1, r.stdout);
      assert.ok(r.stdout.includes('recover_from_artifacts'), r.stdout);
    });
    ok('piano sano → exit 0, advice continue', () => {
      const good = path.join(T, 'audit-good.jsonl');
      fs.writeFileSync(good, JSON.stringify({ ts: 't', bin: 'nmap', ok: true, exit: 0 }) + '\n');
      const r = cli(REC, ['plan', '--audit', good, '--state', opFile, '--logdir', path.join(T, 'nologs'), '--findings', path.join(T, 'nf.jsonl')]);
      assert.strictEqual(r.status, 0, r.stdout);
      assert.ok(r.stdout.includes('"continue"'), r.stdout);
    });
    ok('reconstruction: timeline + opstate + workflow logs aggregati', () => {
      const lib = require(REC);
      const r = lib.plan({ auditFile: audit, stateFile: opFile, logDir: path.join(T, 'nologs'), findingsFile: path.join(T, 'nf.jsonl'), tail: 3 });
      assert.strictEqual(r.reconstruction.audit_lines, 3);
      assert.strictEqual(r.reconstruction.opstate.revision, 1);
      assert.strictEqual(r.reconstruction.last_invocation_ts, '2026-08-26T10:02:00Z');
      assert.ok(Array.isArray(r.reconstruction.workflow_logs));
    });
  }

  // ================================================================ E9 proc-registry
  console.log('E9 — process registry');
  {
    const PR = path.join(WS, 'tools', 'proc-registry.js');
    const regFile = path.join(T, 'proc.json');
    const ENV = { PROC_REGISTRY_FILE: regFile };
    // processo figlio reale (solo stdlib, niente rete)
    const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
    const pid = child.pid;
    ok('register → running', () => {
      const r = cli(PR, ['register', '--task-id', 'scanX', '--pid', String(pid), '--bin', 'node'], ENV);
      assert.strictEqual(r.status, 0, r.stderr);
      assert.ok(JSON.parse(r.stdout).task.status === 'running');
    });
    ok('pause → SIGSTOP (status paused), resume → running, terminate → terminated', () => {
      let r = cli(PR, ['pause', '--task-id', 'scanX'], ENV);
      assert.strictEqual(JSON.parse(r.stdout).task.status, 'paused');
      r = cli(PR, ['resume', '--task-id', 'scanX'], ENV);
      assert.strictEqual(JSON.parse(r.stdout).task.status, 'running');
      r = cli(PR, ['terminate', '--task-id', 'scanX'], ENV);
      assert.strictEqual(JSON.parse(r.stdout).task.status, 'terminated');
    });
    ok('terminate = SIGTERM graceful (mai SIGKILL): il figlio esce pulito', async () => {
      await waitFor(() => { try { process.kill(pid, 0); return false; } catch { return true; } }, 5000);
    });
    ok('task-id sconosciuto → errore fail-closed', () => {
      const r = cli(PR, ['pause', '--task-id', 'ghost'], ENV);
      assert.strictEqual(r.status, 1);
      assert.ok(r.stdout.includes('unknown task_id'), r.stdout);
    });
    ok('registro NON tocca mai pid arbitrari non registrati (nessuna primitiva kill)', () => {
      const exported = Object.keys(require(path.join(WS, 'tools', 'proc-registry')));
      assert.ok(!exported.includes('kill'), 'esporta kill?');
      const r = cli(PR, ['terminate', '--task-id', 'nope'], ENV);
      assert.strictEqual(r.status, 1);
    });
    // hook run.js: --task-id registra a spawn-time e marca exited alla chiusura
    await (async () => {
      try {
        const scopeLoop = path.join(T, 'scope-loop.json');
        fs.writeFileSync(scopeLoop, JSON.stringify({ allowed_ips: ['127.0.0.1'] }));
        const reg2 = path.join(T, 'proc-e2e.json');
        const RUN_ENV = { PROC_REGISTRY_FILE: reg2, SCOPE_JSON: scopeLoop, RUN_AUDIT_FILE: path.join(T, 'audit-e9.jsonl'), AUDIT_DIR: path.join(T, 'audit-e9') };
        const proc = spawn(process.execPath, [path.join(WS, 'tools', 'run.js'), '--task-id', 'e2e-scan', 'node', '-e', 'setTimeout(()=>{},8000)', '127.0.0.1'],
          { cwd: WS, env: { ...process.env, ...RUN_ENV }, stdio: 'ignore' });
        await waitFor(() => fs.existsSync(reg2) && JSON.parse(fs.readFileSync(reg2, 'utf8')).tasks['e2e-scan'], 5000);
        const st = JSON.parse(fs.readFileSync(reg2, 'utf8'));
        assert.strictEqual(st.tasks['e2e-scan'].status, 'running');
        assert.strictEqual(st.tasks['e2e-scan'].via, 'run.js');
        // terminate il figlio a scan in corso → run.js termina
        cli(PR, ['terminate', '--task-id', 'e2e-scan'], { PROC_REGISTRY_FILE: reg2 });
        const code = await new Promise((resolve) => proc.on('close', resolve));
        assert.notStrictEqual(code, 0, 'SIGTERM al figlio → run.js esce non-zero');
        const after = JSON.parse(fs.readFileSync(reg2, 'utf8'));
        assert.strictEqual(after.tasks['e2e-scan'].status, 'exited');
        pass++; console.log('  PASS run.js --task-id: registra il figlio e lo marca exited (e2e)');
      } catch (e) {
        fail++; console.log(`  FAIL run.js --task-id: registra il figlio e lo marca exited (e2e): ${e.message}`);
      }
    })();
    child.kill('SIGKILL'); // cleanup del figlio di test rimasto (MAI via il tool)
  }

  // ================================================================ E4 fleet
  console.log('E4 — fleet dichiarativa');
  {
    const FLEET = path.join(WS, 'tools', 'fleet.js');
    const FLEET_FILE = path.join(WS, 'docs', 'agents-fleet.yaml');
    ok('plan: zero scritture, conteggi red/blue corretti', () => {
      const before = fs.readdirSync(WS).sort();
      const r = cli(FLEET, ['plan'], { FLEET_FILE });
      assert.strictEqual(r.status, 0, r.stderr);
      const f = JSON.parse(r.stdout).fleet;
      assert.strictEqual(f.totals.teams, 2);
      assert.strictEqual(f.totals.agents, 5);
      assert.strictEqual(f.totals.red, 3);
      assert.strictEqual(f.totals.blue, 2);
      assert.deepStrictEqual(fs.readdirSync(WS).sort(), before, 'plan non deve scrivere nulla');
    });
    ok('render: deterministico (2 run byte-identiche) e confinato all outdir', () => {
      const out1 = path.join(T, 'fleet-out1');
      const out2 = path.join(T, 'fleet-out2');
      assert.strictEqual(cli(FLEET, ['render', '--out', out1], { FLEET_FILE }).status, 0);
      assert.strictEqual(cli(FLEET, ['render', '--out', out2], { FLEET_FILE }).status, 0);
      for (const f of ['fleet.json', 'agents-red.md', 'agents-blue.md']) {
        assert.strictEqual(fs.readFileSync(path.join(out1, f), 'utf8'), fs.readFileSync(path.join(out2, f), 'utf8'), f);
      }
    });
    ok('render RIFIUTA HOME / radice (confinamento)', () => {
      for (const bad of [os.homedir(), path.parse(WS).root]) {
        const r = cli(FLEET, ['render', '--out', bad], { FLEET_FILE });
        assert.strictEqual(r.status, 1, 'atteso rifiuto per ' + bad);
        assert.ok(r.stderr.includes('render refused'), r.stderr);
      }
    });
    ok('apply SENZA --yes → rifiuto; con --yes → backup + marker', () => {
      const out = path.join(T, 'fleet-app');
      fs.mkdirSync(out, { recursive: true });
      fs.writeFileSync(path.join(out, 'fleet.json'), '{"legacy":true}\n');
      let r = cli(FLEET, ['apply', '--out', out], { FLEET_FILE });
      assert.notStrictEqual(r.status, 0);
      assert.ok(!fs.existsSync(path.join(out, '.fleet-applied.json')));
      r = cli(FLEET, ['apply', '--yes', '--out', out], { FLEET_FILE });
      assert.strictEqual(r.status, 0, r.stderr);
      assert.ok(fs.existsSync(path.join(out, '.fleet-applied.json')));
      const bks = fs.readdirSync(path.join(out, '.backup-fleet'));
      assert.strictEqual(bks.length, 1);
      assert.ok(fs.readFileSync(path.join(out, '.backup-fleet', bks[0], 'SHA256SUMS'), 'utf8').includes('fleet.json'));
    });
    ok('fleet INVALIDA → fail-closed (color errato, id duplicato)', () => {
      const lib = require(FLEET);
      let errs = lib.validateFleet({ version: 1, name: 'x', teams: [{ name: 'r', color: 'purple', agents: [{ id: 'a', role: 'r', preset: 'p' }] }] });
      assert.ok(errs.some((e) => e.includes('color')), JSON.stringify(errs));
      errs = lib.validateFleet({ version: 1, name: 'x', teams: [
        { name: 'r', color: 'red', agents: [{ id: 'a', role: 'r', preset: 'p' }, { id: 'a', role: 'r2', preset: 'p' }] },
      ] });
      assert.ok(errs.some((e) => e.includes('duplicate agent id')), JSON.stringify(errs));
    });
  }

  // ================================================================ E13 continuation
  console.log('E13 — continuation-advice');
  {
    const CONT = path.join(WS, 'tools', 'continuation.js');
    ok('audit bloccato → advice reduce_scope (recovery della taxonomy run.js)', () => {
      const log = path.join(T, 'cont.jsonl');
      fs.writeFileSync(log, JSON.stringify({ ts: 't1', bin: 'nuclei', blocked: true, error_class: 'scope_blocked', reason: 'x' }) + '\n');
      const r = cli(CONT, ['advise', '--log', log, '--tail', '3']);
      const d = JSON.parse(r.stdout);
      assert.ok(d.advice.some((a) => a.action === 'reduce_scope'), JSON.stringify(d.advice));
    });
    ok('loop (stessa voce ×3) → break_loop, exit 1', () => {
      const log = path.join(T, 'loop.jsonl');
      fs.writeFileSync(log, ['rate limited 429', 'rate limited 429', 'rate limited 429'].map((t) => JSON.stringify({ role: 'agent', text: t })).join('\n') + '\n');
      const r = cli(CONT, ['advise', '--log', log, '--tail', '3']);
      assert.strictEqual(r.status, 1, r.stdout);
      assert.ok(r.stdout.includes('break_loop'), r.stdout);
    });
    ok('tutte in errore → recover_from_artifacts; nessun errore → continue', () => {
      const lib = require(CONT);
      const bad = path.join(T, 'all-bad.jsonl');
      fs.writeFileSync(bad, JSON.stringify({ error: 'boom' }) + '\n' + JSON.stringify({ error: 'boom2' }) + '\n');
      assert.ok(lib.advise({ logFile: bad, tail: 2 }).advice.some((a) => a.action === 'recover_from_artifacts'));
      const good = path.join(T, 'all-good.jsonl');
      fs.writeFileSync(good, JSON.stringify({ role: 'agent', text: 'ok' }) + '\n');
      assert.ok(lib.advise({ logFile: good, tail: 2 }).advice.some((a) => a.action === 'continue'));
    });
  }

  // ================================================================ F9 patch piano a caldo
  console.log('F9 — patch del piano a caldo');
  {
    const WF = path.join(WS, 'tools', 'workflow.js');
    const base = path.join(T, 'f9-base.yaml');
    fs.writeFileSync(base, `name: wf-f9
steps:
  - id: s1
    cmd: node tools/run.js nmap -sn {target}
  - id: s2
    cmd: node tools/run.js nmap -p 1-1000 {target}
    on_error: stop
`);
    const patch = path.join(T, 'f9-patch.yaml');
    fs.writeFileSync(patch, `steps:
  - id: s2
    cmd: node tools/run.js nmap -p 80,443 {target}
    on_error: continue
`);
    ok('--patch: cmd E on_error del subtask sostituiti (goal non riavviato)', () => {
      const r = cli(WF, ['run', base, '-t', 'target.example', '--dry-run', '--patch', patch], { SCOPE_JSON: SCOPE });
      assert.strictEqual(r.status, 0, r.stderr);
      const d = JSON.parse(r.stdout);
      const s2 = d.waves.flatMap((w) => w.steps).find((s) => s.id === 's2');
      assert.ok(s2.cmd.includes('-p 80,443'), s2.cmd);
      assert.strictEqual(s2.on_error, 'continue');
    });
    ok('patch con id INESISTENTE → fail-closed exit 1', () => {
      const bad = path.join(T, 'f9-bad.yaml');
      fs.writeFileSync(bad, 'steps:\n  - id: ghost\n    cmd: node tools/run.js nmap {target}\n');
      const r = cli(WF, ['run', base, '-t', 'target.example', '--dry-run', '--patch', bad], { SCOPE_JSON: SCOPE });
      assert.strictEqual(r.status, 1);
      assert.ok(r.stderr.includes('no step with id') && r.stderr.includes('ghost'), r.stderr);
    });
    ok('validatePatch: cmd fuori dal prefisso run.js → errore', () => {
      const wfLib = require(WF);
      const errs = wfLib.validatePatch({ steps: [{ id: 's1', cmd: 'curl http://x' }] });
      assert.ok(errs.some((e) => e.includes('MUST start with')), JSON.stringify(errs));
    });
  }

  // ================================================================ E11 MCP inverso
  console.log('E11 — MCP bridge (tool guardati esposti, mai broker esterni)');
  {
    const MCP = path.join(WS, 'tools', 'mcp-bridge.js');
    const lib = require(MCP);
    // handleRequest legge lo scope a call-time: punta alla fixture (MAI lo scope reale).
    const SAVED_MCP_SCOPE = process.env.SCOPE_JSON;
    process.env.SCOPE_JSON = SCOPE;
    ok('ping CLI: initialize + tools/list → exit 0', () => {
      const r = cli(MCP, ['ping']);
      assert.strictEqual(r.status, 0, r.stderr);
      // Ondata 6: +3 tool read-only Tier 1 (model.snapshot, planner.plan DRY-RUN, coverage.gaps).
      assert.strictEqual(JSON.parse(r.stdout).tools.length, 7);
    });
    ok('handleRequest: initialize + tools/list whitelist', () => {
      const init = lib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
      assert.ok(init.result && init.result.capabilities);
      const list = lib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }));
      assert.deepStrictEqual(list.result.tools.map((t) => t.name),
        ['scope.check', 'run.dryRun', 'gate.status', 'model.snapshot', 'planner.plan', 'coverage.gaps', 'system.info']);
    });
    ok('scope.check: in-scope ok, out-of-scope deny (deny-by-default)', () => {
      const inR = lib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'scope.check', arguments: { url: 'http://target.example/' } } }));
      const txt = JSON.parse(inR.result.content[0].text);
      assert.strictEqual(txt.ok, true);
      const outR = lib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scope.check', arguments: { url: 'http://10.9.9.9/' } } }));
      assert.strictEqual(JSON.parse(outR.result.content[0].text).ok, false);
    });
    ok('run.dryRun: verdetto gating senza mai eseguire', () => {
      const r = lib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'run.dryRun', arguments: { bin: 'nmap', args: ['-sn', 'http://target.example/'] } } }));
      const txt = JSON.parse(r.result.content[0].text);
      assert.ok(txt.verdict && txt.verdict.dry_run === true, txt.stdout || txt.stderr || '');
      assert.strictEqual(txt.verdict.verdict, 'in scope');
    });
    ok('tool sconosciuto → -32601; JSON rotto → -32700; metodo ignoto → -32601', () => {
      const u = lib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'evil', arguments: {} } }));
      assert.strictEqual(u.error.code, -32601);
      const p = lib.handleRequest('{broken');
      assert.strictEqual(p.error.code, -32700);
      const m = lib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'foo', params: {} }));
      assert.strictEqual(m.error.code, -32601);
    });
    ok('server stdio e2e: risposta per riga su stdout (spawn)', async () => {
      const scopeLoop = path.join(T, 'mcp-scope.json');
      fs.writeFileSync(scopeLoop, JSON.stringify({ targets: ['target.example'] }));
      const child = spawn(process.execPath, [MCP], { env: { ...process.env, SCOPE_JSON: scopeLoop }, stdio: ['pipe', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (d) => (out += d));
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) + '\n');
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scope.check', arguments: { url: 'http://target.example/' } } }) + '\n');
      child.stdin.end();
      await new Promise((resolve) => child.on('close', resolve));
      const lines = out.trim().split('\n').map(JSON.parse);
      assert.strictEqual(lines[0].result.tools.length, 4);
      assert.strictEqual(JSON.parse(lines[1].result.content[0].text).ok, true);
    });
    if (SAVED_MCP_SCOPE === undefined) delete process.env.SCOPE_JSON; else process.env.SCOPE_JSON = SAVED_MCP_SCOPE;
  }

  console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
  fs.rmSync(T, { recursive: true, force: true });
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
