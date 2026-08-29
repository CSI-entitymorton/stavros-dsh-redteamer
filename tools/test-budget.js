#!/usr/bin/env node
// Zero-dependency OFFLINE test for tools/budget.js (B1 engagement-cap + F2 per-classe).
// Eredita lo stile di tools/test-gate.js: stampa PASS/FAIL per caso, exit 1 se almeno un FAIL.
//
// Proprietà:
//   - nessuna rete, solo stdlib Node;
//   - tutte le fixture (config/state/audit/counters/classes/token-log) vengono generate in una
//     directory TEMPORANEA (os.tmpdir()); i path REALI del workspace non vengono MAI toccati:
//     ogni invocazione CLI passa esplicitamente --config/--state/--audit/--counters-dir/--classes.
//   - deterministico: il caso wall-clock pre-seeda budget.started_at nel passato invece di dormire.
//
// Run: node tools/test-budget.js

'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TOOL = path.join(__dirname, 'budget.js');

let pass = 0, fail = 0;
function ok(name, fn) {
  // fn() usa assert: un throw = FAIL con messaggio dell'assert.
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name} :: ${String(e.message).split('\n')[0]}`); }
}

// ---- fixture helpers --------------------------------------------------------
function mkfixture(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-budget-test-' + tag + '-'));
}

function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n');
}

function writeLines(file, lines) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, lines.map((l) => JSON.stringify(l)).join('\n') + (lines.length ? '\n' : ''));
}

// Invocazione CLI ermetica: env pulito dalle variabili BUDGET/DSH ereditate + override per-run.
function runBudget(args, extraEnv) {
  const env = {};
  for (const k of Object.keys(process.env)) {
    if (!/^(BUDGET_|DSH_TOKEN_USAGE_FILE|RUN_AUDIT_FILE)/.test(k)) env[k] = process.env[k];
  }
  Object.assign(env, extraEnv || {});
  return spawnSync(process.execPath, [TOOL].concat(args), { encoding: 'utf8', env });
}

const ENGAGEMENT_CFG = { max_requests: 5, max_wall_minutes: 90, max_tokens: 400, grace_note: 'stop graceful' };

console.log('# tools/budget.js — B1/F2');

// --- gruppo 1: misconfig -> mai bloccare -------------------------------------
{
  const fx = mkfixture('a');
  try {
    const r = runBudget(['check', '--config', path.join(fx, 'assente.json'), '--state', path.join(fx, 'state.json'), '--audit', path.join(fx, 'audit.jsonl')]);
    const out = JSON.parse(r.stdout);
    ok('B1 check senza config -> {enabled:false} exit 0', () => {
      assert.strictEqual(r.status, 0);
      assert.strictEqual(out.enabled, false);
      assert.strictEqual(out.halted, false);
    });
    const cfgCorrupt = path.join(fx, 'corrotto.json');
    fs.writeFileSync(cfgCorrupt, '{non-json-valido');
    const r2 = runBudget(['check', '--config', cfgCorrupt, '--state', path.join(fx, 'state.json'), '--audit', path.join(fx, 'audit.jsonl')]);
    ok('B1 config corrotto -> {enabled:false} exit 0 (fail-open su misconfig)', () => {
      assert.strictEqual(r2.status, 0);
      assert.strictEqual(JSON.parse(r2.stdout).enabled, false);
      assert.ok(/CORRUPT|UNREADABLE/.test(JSON.parse(r2.stdout).note));
    });
    const r3 = runBudget([]);
    ok('uso errato (nessun comando) -> exit 2', () => assert.strictEqual(r3.status, 2));
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 2: sotto soglia + seed started_at --------------------------------
{
  const fx = mkfixture('b');
  try {
    const cfg = path.join(fx, 'budget.json');
    const state = path.join(fx, 'operation-state.json');
    const audit = path.join(fx, 'audit.jsonl');
    writeJson(cfg, ENGAGEMENT_CFG);
    writeLines(audit, [{ bin: 'nmap', args: ['-p', '80'] }, { bin: 'nmap', args: ['-p', '443'] }]); // 2 <= 5
    const r = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit]);
    const out = JSON.parse(r.stdout);
    ok('B1 sotto soglia -> exit 0, counters corretti', () => {
      assert.strictEqual(r.status, 0);
      assert.strictEqual(out.enabled, true);
      assert.deepStrictEqual(out.exceeded, []);
      assert.strictEqual(out.counters.requests, 2);
    });
    const st = JSON.parse(fs.readFileSync(state, 'utf8'));
    ok('B1 prima check seeda budget.started_at nello stato', () => {
      assert.ok(st.budget && typeof st.budget.started_at === 'string');
      assert.ok(!Number.isNaN(Date.parse(st.budget.started_at)));
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 3: superamento requests -> exit 3 + snapshot + halt persistente ---
{
  const fx = mkfixture('c');
  try {
    const cfg = path.join(fx, 'budget.json');
    const state = path.join(fx, 'operation-state.json');
    const audit = path.join(fx, 'audit.jsonl');
    writeJson(cfg, ENGAGEMENT_CFG);
    // Stato pre-esistente con campi ALTRI che devono sopravvivere alla write atomica.
    writeJson(state, { version: 1, goal: 'test-goal', custom_keep: 'PRESERVAMI', created_at: '2026-08-26T00:00:00.000Z' });
    const lines = [];
    for (let i = 0; i < 7; i++) lines.push({ bin: 'ffuf', args: ['-w', 'list.txt', '-u', 'http://target.example/FUZZ'] }); // 7 > 5
    writeLines(audit, lines);

    const r1 = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit]);
    const o1 = JSON.parse(r1.stdout);
    ok('B1 oltre max_requests -> exit 3', () => {
      assert.strictEqual(r1.status, 3);
      assert.strictEqual(o1.halted, true);
      assert.ok(o1.exceeded.some((e) => e.cap === 'max_requests'));
    });
    ok('B1 banner OPERATOR REQUEST REQUIRED su stderr', () => {
      assert.ok(r1.stderr.includes('OPERATOR REQUEST REQUIRED'));
    });
    const st1 = JSON.parse(fs.readFileSync(state, 'utf8'));
    ok('B1 operation-state.budget={halted:true,...} + history[] append', () => {
      assert.strictEqual(st1.budget.halted, true);
      assert.ok(Array.isArray(st1.budget.history) && st1.budget.history.some((h) => h.action === 'halt'));
      assert.strictEqual(st1.custom_keep, 'PRESERVAMI'); // write atomica preserva gli altri campi
      assert.strictEqual(st1.goal, 'test-goal');
    });
    ok('B1 snapshot operation-state.snapshot-<ISOts>.json creato accanto allo stato', () => {
      const snaps = fs.readdirSync(fx).filter((f) => /^operation-state\.snapshot-\d{4}-\d{2}-\d{2}T.+\.json$/.test(f));
      assert.ok(snaps.length >= 1, 'snapshot mancante in ' + fx);
      assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(fx, snaps[0]), 'utf8')).custom_keep, 'PRESERVAMI');
    });

    // Halt persistente: anche spostando il contatore sotto soglia resta exit 3 finche' no reset.
    const audit2 = path.join(fx, 'audit-vuoto.jsonl');
    writeLines(audit2, []);
    const r2 = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit2]);
    ok('B1 resta halted (exit 3) finche\' l\'operatore non fa reset', () => {
      assert.strictEqual(r2.status, 3);
      assert.ok(/halt pregresso|reset/i.test(r2.stderr));
    });

    const r3 = runBudget(['reset', '--state', state]);
    ok('reset senza --reason -> exit 2 (disciplina operatore)', () => assert.strictEqual(r3.status, 2));

    const r4 = runBudget(['reset', '--reason', 'finestra estesa dall\'operatore', '--state', state, '--audit', audit2]);
    const st4 = JSON.parse(fs.readFileSync(state, 'utf8'));
    ok('reset --reason -> exit 0, halted=false, baseline, history reset', () => {
      assert.strictEqual(r4.status, 0);
      assert.strictEqual(st4.budget.halted, false);
      assert.strictEqual(st4.budget.baseline.requests, 0);
      assert.ok(st4.budget.history.some((h) => h.action === 'reset'));
    });

    // Delta semantics: 6 righe assolute ma baseline=0 -> sotto soglia di nuovo (cap 5, 6>5? NO:
    // l'audit attivo e' audit2 vuoto => requests=0). Aggiungiamo righe fino a 4 delta: exit 0.
    writeLines(audit2, [{ bin: 'x' }, { bin: 'x' }, { bin: 'x' }, { bin: 'x' }]);
    const r5 = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit2]);
    ok('B1 dopo reset i cap valutano il delta dal reset -> exit 0 sotto soglia', () => {
      assert.strictEqual(r5.status, 0);
      assert.strictEqual(JSON.parse(r5.stdout).effective.requests, 4);
    });
    // Superamento post-reset: 6 delta > 5 -> exit 3 di nuovo (nuovo periodo).
    writeLines(audit2, [{ bin: 'x' }, { bin: 'x' }, { bin: 'x' }, { bin: 'x' }, { bin: 'x' }, { bin: 'x' }]);
    const r6 = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit2]);
    ok('B1 nuovo periodo: delta oltre cap -> exit 3 di nuovo', () => assert.strictEqual(r6.status, 3));
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 4: wall-clock (deterministico via started_at pre-seedato) --------
{
  const fx = mkfixture('d');
  try {
    const cfg = path.join(fx, 'budget.json');
    const state = path.join(fx, 'operation-state.json');
    const audit = path.join(fx, 'audit.jsonl');
    writeJson(cfg, ENGAGEMENT_CFG);
    const old = new Date(Date.now() - 120 * 60 * 1000).toISOString(); // 120 min fa
    writeJson(state, { version: 1, budget: { started_at: old } });
    writeLines(audit, []);
    const r = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit]);
    const o = JSON.parse(r.stdout);
    ok('B1 wall-clock oltre max_wall_minutes -> exit 3 (started_at 120m fa, cap 90m)', () => {
      assert.strictEqual(r.status, 3);
      assert.ok(o.exceeded.some((e) => e.cap === 'max_wall_minutes' && e.observed >= 120));
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 5: token counter via DSH_TOKEN_USAGE_FILE -------------------------
{
  const fx = mkfixture('e');
  try {
    const cfg = path.join(fx, 'budget.json');
    const state = path.join(fx, 'operation-state.json');
    const audit = path.join(fx, 'audit.jsonl');
    const tok = path.join(fx, 'tokens.jsonl');
    writeJson(cfg, ENGAGEMENT_CFG);
    writeLines(audit, []);
    writeLines(tok, [{ tokens: 150 }, { tokens: 150 }, { tokens: 50 }, { junk: true }]); // somma 350 <= 400

    const rOk = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit], { DSH_TOKEN_USAGE_FILE: tok });
    ok('B1 tokens sotto cap -> exit 0, tokens=350', () => {
      assert.strictEqual(rOk.status, 0);
      assert.strictEqual(JSON.parse(rOk.stdout).counters.tokens, 350);
    });

    fs.appendFileSync(tok, JSON.stringify({ tokens: 100 }) + '\n'); // 450 > 400
    const rOver = runBudget(['check', '--config', cfg, '--state', state, '--audit', audit], { DSH_TOKEN_USAGE_FILE: tok });
    ok('B1 tokens sopra max_tokens -> exit 3', () => {
      assert.strictEqual(rOver.status, 3);
      assert.ok(JSON.parse(rOver.stdout).exceeded.some((e) => e.cap === 'max_tokens' && e.observed === 450));
    });

    const rNoEnv = runBudget(['check', '--config', cfg, '--state', path.join(fx, 's2.json'), '--audit', audit]);
    ok('B1 cap token dichiarato ma DSH_TOKEN_USAGE_FILE assente -> NON superamento, nota token_source_absent', () => {
      assert.strictEqual(rNoEnv.status, 0);
      const o = JSON.parse(rNoEnv.stdout);
      assert.strictEqual(o.counters.tokens, null);
      assert.ok(o.notes.some((n) => /token_source_absent|token non disponibile/i.test(n)));
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 6: F2 per-classe (tick/check, exit 4 distinto) --------------------
{
  const fx = mkfixture('f');
  try {
    const cfg = path.join(fx, 'budget.json');
    const classes = path.join(fx, 'budgets.json');
    const state = path.join(fx, 'operation-state.json');
    const audit = path.join(fx, 'audit.jsonl');
    const cdir = path.join(fx, 'counters');
    writeJson(cfg, ENGAGEMENT_CFG);
    writeJson(classes, { classes: { general: { max_tool_calls: 100 }, limited: { max_tool_calls: 2 } } });
    writeLines(audit, []);

    const base = ['--config', cfg, '--state', state, '--audit', audit, '--counters-dir', cdir, '--classes', classes];

    const t1 = runBudget(['tick', '--agent-class', 'limited'].concat(base));
    const t2 = runBudget(['tick', '--agent-class', 'limited'].concat(base));
    ok('F2 tick limited x2 (cap 2) -> exit 0, contatore su tool-calls-limited.jsonl', () => {
      assert.strictEqual(t1.status, 0);
      assert.strictEqual(t2.status, 0);
      assert.strictEqual(JSON.parse(t2.stdout).tool_calls, 2);
      assert.ok(fs.existsSync(path.join(cdir, 'tool-calls-limited.jsonl')));
    });

    const t3 = runBudget(['tick', '--agent-class', 'limited'].concat(base));
    const o3 = JSON.parse(t3.stdout);
    ok('F2 terzo tick oltre max_tool_calls -> exit 4 (distinto dal 3) + halt classe', () => {
      assert.strictEqual(t3.status, 4);
      assert.strictEqual(o3.exceeded, true);
      assert.strictEqual(o3.halted, true);
      assert.ok(t3.stderr.includes('OPERATOR REQUEST REQUIRED (class limited)'));
    });
    const st3 = JSON.parse(fs.readFileSync(state, 'utf8'));
    ok('F2 nota per-classe in operation-state.budget.classes[limited]', () => {
      assert.strictEqual(st3.budget.classes.limited.halted, true);
      assert.strictEqual(st3.budget.classes.limited.max_tool_calls, 2);
      assert.ok(st3.budget.history.some((h) => h.action === 'halt-class' && h.class === 'limited'));
    });

    const t4 = runBudget(['tick', '--agent-class', 'limited'].concat(base));
    ok('F2 tick mentre halted -> exit 4 e contatore NON incrementa (fail-closed)', () => {
      assert.strictEqual(t4.status, 4);
      assert.strictEqual(JSON.parse(t4.stdout).tool_calls, 3);
    });

    const ckL = runBudget(['check', '--agent-class', 'limited'].concat(base));
    ok('F2 check --agent-class limited dopo halt -> exit 4', () => assert.strictEqual(ckL.status, 4));

    const ckG = runBudget(['check', '--agent-class', 'general'].concat(base));
    ok('F2 check --agent-class general (sotto cap) -> exit 0', () => {
      assert.strictEqual(ckG.status, 0);
      assert.strictEqual(JSON.parse(ckG.stdout).class_budgets_enabled, true);
    });

    const ckU = runBudget(['check', '--agent-class', 'inesistente'].concat(base));
    ok('F2 classe sconosciuta -> exit 2', () => assert.strictEqual(ckU.status, 2));
    const tSlash = runBudget(['tick', '--agent-class', '../evil'].concat(base));
    ok('F2 nome classe non sicuro (traversal) -> exit 2', () => assert.strictEqual(tSlash.status, 2));
    const tkNone = runBudget(['tick'].concat(base));
    ok('tick senza --agent-class -> exit 2 (usage)', () => assert.strictEqual(tkNone.status, 2));

    const rs = runBudget(['reset', '--reason', 'rafforzamento quota classe', '--state', state, '--audit', audit]);
    const stR = JSON.parse(fs.readFileSync(state, 'utf8'));
    ok('reset sblocca anche le classi haltate (halted:false)', () => {
      assert.strictEqual(rs.status, 0);
      assert.strictEqual(stR.budget.classes.limited.halted, false);
      const ckL2 = runBudget(['check', '--agent-class', 'limited'].concat(base));
      assert.strictEqual(ckL2.status, 0);
    });

    // F2 con budgets.json assente: tick segnala disabilitato, non blocca (misconfig fail-open).
    const tNoCls = runBudget(['tick', '--agent-class', 'general', '--config', cfg, '--state', state,
      '--audit', audit, '--counters-dir', cdir, '--classes', path.join(fx, 'nope.json')]);
    ok('F2 budgets.json assente -> tick non blocca, segnala class_budgets_enabled:false', () => {
      assert.strictEqual(tNoCls.status, 0);
      assert.strictEqual(JSON.parse(tNoCls.stdout).class_budgets_enabled, false);
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 7: libreria (require, senza spawn) --------------------------------
{
  const b = require('./budget.js');
  ok('export libreria presenti (resolvePaths/evaluateEngagement/countLines/CLASS_NAME_RE)', () => {
    assert.strictEqual(typeof b.evaluateEngagement, 'function');
    assert.strictEqual(b.CLASS_NAME_RE.test('limited'), true);
    assert.strictEqual(b.CLASS_NAME_RE.test('../evil'), false);
    assert.strictEqual(b.countLines('/percorso/che/non/esiste.jsonl'), 0);
  });
  ok('evaluateEngagement: effReq = osservato - baseline (delta)', () => {
    const r = b.evaluateEngagement({ max_requests: 5 }, { requests: 12, wall_minutes_raw: 1, tokens: null }, { requests: 10 });
    assert.strictEqual(r.effective.requests, 2);
    assert.deepStrictEqual(r.exceeded, []);
  });
}

console.log(`\nbudget: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
