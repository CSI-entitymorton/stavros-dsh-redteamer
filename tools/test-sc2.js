#!/usr/bin/env node
// Ondata 3 — SC2 test suite:
//   C2w : tools/opstate.js — revisione CAS (rifiuto su revisione stantia), transizioni
//         APPEND-ONLY, lease per sub-agent (owner+scadenza), integrazione con budget.js
//         (.budget intatto, stessi helper IO, write atomici senza residui .tmp).
//   F5  : tools/artifact-ledger.js — record/verify/show/evidence + hook additivo in
//         workflow.js (artifacts reali → ledger, mai bloccante).
// Tutto offline: fixture in mkdtemp, env override (OPSTATE_FILE/BUDGET_*/ARTIFACT_LEDGER_FILE/
// EVIDENCE_INDEX_FILE/WORKFLOW_LOG_DIR/COVERAGE_WORKFLOW_FILE/SCOPE_JSON).
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
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
const OPSTATE = path.join(WS, 'tools', 'opstate.js');
const LEDGER = path.join(WS, 'tools', 'artifact-ledger.js');
const WORKFLOW = path.join(WS, 'tools', 'workflow.js');
const opstateLib = require(OPSTATE);
const ledgerLib = require(LEDGER);

function cli(args, env) {
  return spawnSync(process.execPath, [OPSTATE, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 20000 });
}

async function main() {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'sc2-'));
  const stateFile = path.join(T, 'operation-state.json');
  const ENV = { OPSTATE_FILE: stateFile };

  // ---------------------------------------------------------------- C2w core
  console.log('C2w — opstate: revisione CAS + transizioni append-only');
  ok('mutate senza expect: revisione 0->1, transition seq=1 appesa', () => {
    const r = cli(['mutate', '--owner', 'orchestrator', '--action', 'begin-step', '--detail', '{"step":"recon"}'], ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    const st = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    assert.strictEqual(st.revision, 1);
    assert.strictEqual(st.transitions.length, 1);
    assert.strictEqual(st.transitions[0].seq, 1);
    assert.strictEqual(st.transitions[0].owner, 'orchestrator');
    assert.deepStrictEqual(st.transitions[0].detail, { step: 'recon' });
  });
  ok('CAS: --expect-revision stantia -> exit 3 e FILE NON TOCCATO', () => {
    const before = fs.readFileSync(stateFile, 'utf8');
    const r = cli(['mutate', '--owner', 'agent-b', '--action', 'stale-write', '--expect-revision', '0'], ENV);
    assert.strictEqual(r.status, 3, r.stderr);
    assert.ok(r.stderr.includes('stale-revision'), r.stderr.slice(0, 200));
    assert.strictEqual(fs.readFileSync(stateFile, 'utf8'), before, 'lo stato non deve cambiare su rifiuto CAS');
  });
  ok('CAS riuscito con revisione corretta: revision incrementa, append-only preservato', () => {
    const snapBefore = fs.readFileSync(stateFile, 'utf8');
    const parsedBefore = JSON.parse(snapBefore);
    const r = cli(['mutate', '--owner', 'agent-a', '--action', 'note', '--expect-revision', '1'], ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    const st = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    assert.strictEqual(st.revision, 2);
    // append-only: le vecchie transizioni sono BYTE-IDENTICHE e in ordine
    assert.deepStrictEqual(st.transitions.slice(0, parsedBefore.transitions.length), parsedBefore.transitions);
    assert.ok(st.transitions.every((t, i) => t.seq === i + 1), 'seq monotoniche');
  });
  ok('libreria casUpdate: mutator che throwa NON scrive nulla', () => {
    const revBefore = opstateLib.loadOpState(stateFile).revision;
    let threw = false;
    try {
      opstateLib.casUpdate(stateFile, revBefore, () => { throw new Error('boom'); }, { owner: 't', action: 'boom' });
    } catch (e) { threw = true; }
    assert.ok(threw);
    assert.strictEqual(opstateLib.loadOpState(stateFile).revision, revBefore, 'revisione immutata');
  });
  ok('nessun residuo .tmp dopo le scritture (atomicità tmp+rename)', () => {
    const leftovers = fs.readdirSync(T).filter((f) => f.includes('.tmp-'));
    assert.deepStrictEqual(leftovers, []);
  });

  console.log('C2w — lease per sub-agent');
  ok('acquire -> grant con scadenza; show riporta il lease', () => {
    const r = cli(['lease', 'acquire', '--resource', 'host-192.168.0.94', '--owner', 'scanner-1', '--ttl', '60'], ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    const s = JSON.parse(cli(['show'], ENV).stdout);
    assert.strictEqual(s.leases['host-192.168.0.94'].owner, 'scanner-1');
    assert.strictEqual(s.leases['host-192.168.0.94'].expired, false);
  });
  ok('conflitto: acquire da altro owner mentre trattenuto -> exit 4 con holder', () => {
    const r = cli(['lease', 'acquire', '--resource', 'host-192.168.0.94', '--owner', 'scanner-2', '--ttl', '60'], ENV);
    assert.strictEqual(r.status, 4, r.stderr);
    assert.ok(r.stderr.includes('"holder":"scanner-1"'), r.stderr.slice(0, 300));
  });
  await okAsync('renew dal titolare estende la scadenza', async () => {
    const before = JSON.parse(cli(['show'], ENV).stdout).leases['host-192.168.0.94'].expires_at;
    await new Promise((res) => setTimeout(res, 30));
    const r = cli(['lease', 'renew', '--resource', 'host-192.168.0.94', '--owner', 'scanner-1', '--ttl', '120'], ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    const after = JSON.parse(cli(['show'], ENV).stdout).leases['host-192.168.0.94'].expires_at;
    assert.ok(Date.parse(after) > Date.parse(before));
  });
  ok('release da NON-titolare (non scaduto) -> rifiutato exit 4', () => {
    const r = cli(['lease', 'release', '--resource', 'host-192.168.0.94', '--owner', 'scanner-2'], ENV);
    assert.strictEqual(r.status, 4, r.stderr);
  });
  await okAsync('scadenza pigra: ttl breve -> altro owner acquisisce dopo expiry', async () => {
    const r1 = cli(['lease', 'acquire', '--resource', 'port-sweep', '--owner', 'short-holder', '--ttl', '1'], ENV);
    assert.strictEqual(r1.status, 0);
    await new Promise((res) => setTimeout(res, 1600)); // margine ampio oltre ttl=1s (spawn overhead)
    const r2 = cli(['lease', 'acquire', '--resource', 'port-sweep', '--owner', 'next-agent', '--ttl', '60'], ENV);
    assert.strictEqual(r2.status, 0, r2.stderr);
    const s = JSON.parse(cli(['show'], ENV).stdout);
    assert.strictEqual(s.leases['port-sweep'].owner, 'next-agent', 'dopo scadenza il lease deve appartenere a next-agent');
  });
  ok('release dal titolare chiude il lease', () => {
    const r = cli(['lease', 'release', '--resource', 'port-sweep', '--owner', 'next-agent'], ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    const s = JSON.parse(cli(['show'], ENV).stdout);
    assert.strictEqual(s.leases['port-sweep'], undefined);
  });

  console.log('C2w — integrazione budget.js (INTEGRA, non spezza)');
  const classesFile = path.join(T, 'budgets.json');
  fs.writeFileSync(classesFile, JSON.stringify({ classes: { general: { max_tool_calls: 2 } } }));
  const cfgFile = path.join(T, 'budget.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ max_requests: 1000000 })); // engagement config presente -> check valuta anche le classi
  const auditFile = path.join(T, 'run-audit.jsonl');
  const budgetEnv = { BUDGET_STATE_FILE: stateFile, BUDGET_CLASSES_FILE: classesFile, BUDGET_CONFIG_FILE: cfgFile, RUN_AUDIT_FILE: auditFile };
  ok('budget tick/check scrivono .budget nello STESSO stato; opstate continua a funzionare', () => {
    // due tick -> cap classe superato (max_tool_calls 2, delta>2 al terzo)
    const t1 = spawnSync(process.execPath, [path.join(WS, 'tools', 'budget.js'), 'tick', '--agent-class', 'general'], { encoding: 'utf8', env: { ...process.env, ...budgetEnv } });
    const t2 = spawnSync(process.execPath, [path.join(WS, 'tools', 'budget.js'), 'tick', '--agent-class', 'general'], { encoding: 'utf8', env: { ...process.env, ...budgetEnv } });
    const t3 = spawnSync(process.execPath, [path.join(WS, 'tools', 'budget.js'), 'tick', '--agent-class', 'general'], { encoding: 'utf8', env: { ...process.env, ...budgetEnv } });
    assert.strictEqual(t1.status, 0); assert.strictEqual(t2.status, 0);
    assert.strictEqual(t3.status, 4, 'il terzo tick deve haltare la classe'); // F2 semantics
    const st = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    assert.strictEqual(st.budget.classes.general.halted, true, '.budget scritto da budget.js');
    const revBefore = st.revision;
    // opstate opera SOPRA lo stesso file senza rompere .budget
    const m = cli(['mutate', '--owner', 'agent-c', '--action', 'post-budget-note'], ENV);
    assert.strictEqual(m.status, 0, m.stderr);
    const st2 = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    assert.strictEqual(st2.revision, revBefore + 1, 'revision incrementata solo da opstate');
    assert.strictEqual(st2.budget.classes.general.halted, true, '.budget PRESERVATO dalla scrittura opstate');
    assert.strictEqual(st2.transitions[st2.transitions.length - 1].action, 'post-budget-note');
    // budget rilegge lo stato dopo le scritture opstate: la sua view resta coerente
    const chk = spawnSync(process.execPath, [path.join(WS, 'tools', 'budget.js'), 'check', '--agent-class', 'general'], { encoding: 'utf8', env: { ...process.env, ...budgetEnv } });
    assert.strictEqual(chk.status, 4, 'halt di classe ancora attivo anche dopo scritture opstate (stdout: ' + chk.stdout.slice(0, 300) + ')');
    const chkState = JSON.parse(chk.stdout);
    assert.strictEqual(chkState.class_halted, true);
    // e un ulteriore tick resta bloccato (fail-closed intatto)
    const t4 = spawnSync(process.execPath, [path.join(WS, 'tools', 'budget.js'), 'tick', '--agent-class', 'general'], { encoding: 'utf8', env: { ...process.env, ...budgetEnv } });
    assert.strictEqual(t4.status, 4, 'tick su classe haltata deve restare exit 4');
  });

  // ---------------------------------------------------------------- F5 ledger
  console.log('F5 — artifact-ledger: record/verify/show/evidence');
  const ledFile = path.join(T, 'artifact-ledger.jsonl');
  const artA = path.join(T, 'nmap-output.txt');
  const artB = path.join(T, 'httpx-output.json');
  fs.writeFileSync(artA, 'PORT STATE\n80 open\n');
  fs.writeFileSync(artB, '[{"url":"http://target.example/","status":200}]\n');
  ok('record: sha256+bytes corretti, seq progressivi', () => {
    const r = spawnSync(process.execPath, [LEDGER, 'record', '--action', 'enum:http', '--producer', 'workflow:test-wf:s1',
      '--artifact', artA, '--artifact', artB, '--exit', '0', '--ledger', ledFile,
      '--params', '{"target":"target.example"}'], { encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stderr);
    const entries = ledgerLib.readEntries(ledFile);
    assert.strictEqual(entries.length, 2);
    const wantA = crypto.createHash('sha256').update(fs.readFileSync(artA)).digest('hex');
    assert.strictEqual(entries[0].sha256, wantA);
    assert.strictEqual(entries[0].seq, 1);
    assert.strictEqual(entries[1].seq, 2);
    assert.deepStrictEqual(entries[0].params, { target: 'target.example' });
  });
  ok('record artefatto INESISTENTE -> rifiutato, niente righe aggiunte', () => {
    const before = ledgerLib.readEntries(ledFile).length;
    const r = spawnSync(process.execPath, [LEDGER, 'record', '--action', 'ghost', '--artifact', path.join(T, 'nope.bin'), '--ledger', ledFile], { encoding: 'utf8' });
    assert.notStrictEqual(r.status, 0);
    assert.strictEqual(ledgerLib.readEntries(ledFile).length, before);
  });
  ok('verify: intact -> exit 0', () => {
    const r = spawnSync(process.execPath, [LEDGER, 'verify', '--ledger', ledFile], { encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stdout);
    assert.ok(r.stdout.includes('"verdict": "intact"'));
  });
  ok('verify AVVERSARIALE: artefatto manomesso -> hash_mismatch exit≠0; mancante -> missing', () => {
    fs.appendFileSync(artB, '{"url":"http://target.example/injected","status":200}\n');
    let r = spawnSync(process.execPath, [LEDGER, 'verify', '--ledger', ledFile], { encoding: 'utf8' });
    assert.notStrictEqual(r.status, 0);
    assert.ok(r.stdout.includes('hash_mismatch') && !r.stdout.includes('"hash_mismatch": []'), r.stdout.slice(0, 300));
    fs.rmSync(artA);
    r = spawnSync(process.execPath, [LEDGER, 'verify', '--ledger', ledFile], { encoding: 'utf8' });
    assert.notStrictEqual(r.status, 0);
    assert.ok(r.stdout.includes('"missing"'), r.stdout.slice(0, 300));
  });
  ok('evidence: righe E- single-writer, una per azione, con hash corto', () => {
    const ei = path.join(T, 'evidence-index.md');
    fs.writeFileSync(ei, '| E-004 | 2026-08-26 | `x` | y | z |\n');
    // ricrea artA (era stato rimosso nel test avversariale) per un ledger verificabile
    fs.writeFileSync(artA, 'PORT STATE\n80 open\n');
    const r = spawnSync(process.execPath, [LEDGER, 'evidence', '--evidence-index', ei, '--ledger', ledFile], { encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stderr);
    const txt = fs.readFileSync(ei, 'utf8');
    assert.ok(/^\| E-005 \|.*artifact-ledger azione `enum:http`/m.test(txt), txt);
    assert.ok(txt.includes('#' + crypto.createHash('sha256').update(fs.readFileSync(artA)).digest('hex').slice(0, 12)));
  });

  console.log('F5 — hook additivo in workflow.js (artifacts reali -> ledger)');
  ok('workflow run registra le artifacts esistenti nel ledger senza bloccare il run', () => {
    const W = path.join(T, 'wf');
    fs.mkdirSync(path.join(W, 'reports', 'tmp'), { recursive: true });
    const scopeFile = path.join(W, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({ targets: ['target.example'], exclusions: [] }));
    const artifact = path.join(W, 'reports', 'enum-out.txt');
    fs.writeFileSync(artifact, 'simulated artifact\n'); // prodotto PRIMA (esistenza reale)
    const yaml = [
      'name: ledger-test-wf',
      'steps:',
      '  - id: enum-step',
      '    cmd: node tools/run.js cat http://target.example/not-a-real-file',
      '    on_error: continue',
      '    artifacts:',
      '      - path: ' + artifact,
      '        surface: enum-output',
      '',
    ].join('\n');
    const wfFile = path.join(W, 'wf.yaml');
    fs.writeFileSync(wfFile, yaml);
    const env = {
      ...process.env,
      SCOPE_JSON: scopeFile,
      WORKFLOW_LOG_DIR: path.join(W, 'reports', 'tmp', 'workflow'),
      COVERAGE_WORKFLOW_FILE: path.join(W, 'reports', 'tmp', 'coverage-workflow.json'),
      EVIDENCE_INDEX_FILE: path.join(W, 'evidence-index.md'),
      ARTIFACT_LEDGER_FILE: path.join(W, 'reports', 'tmp', 'artifact-ledger.jsonl'),
    };
    const r = spawnSync(process.execPath, [WORKFLOW, 'run', wfFile, '-t', 'target.example'], { encoding: 'utf8', env, timeout: 60000 });
    assert.ok(r.stdout.includes('"artifacts_ledgered": 1'), 'summary deve contare 1 artifact ledgered:\n' + r.stdout.slice(0, 600));
    const entries = ledgerLib.readEntries(env.ARTIFACT_LEDGER_FILE);
    assert.strictEqual(entries.length, 1);
    assert.strictEqual(entries[0].producer, 'workflow');
    assert.strictEqual(entries[0].action_id, 'workflow:ledger-test-wf:enum-step');
    assert.strictEqual(entries[0].kind, 'enum-output');
  });
  ok('dry-run NON tocca il ledger (E7 resta valido)', () => {
    const W = path.join(T, 'wf2');
    fs.mkdirSync(W, { recursive: true });
    const scopeFile = path.join(W, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({ targets: ['target.example'], exclusions: [] }));
    const wfFile = path.join(W, 'wf.yaml');
    fs.writeFileSync(wfFile, 'name: dry-wf\nsteps:\n  - id: s1\n    cmd: node tools/run.js cat http://target.example/x\n    on_error: continue\n');
    const ledFile = path.join(W, 'led.jsonl');
    const env = { ...process.env, SCOPE_JSON: scopeFile, ARTIFACT_LEDGER_FILE: ledFile };
    const r = spawnSync(process.execPath, [WORKFLOW, 'run', wfFile, '-t', 'target.example', '--dry-run'], { encoding: 'utf8', env, timeout: 30000 });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(!fs.existsSync(ledFile), 'dry-run non deve scrivere il ledger');
  });

  console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
  fs.rmSync(T, { recursive: true, force: true });
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
