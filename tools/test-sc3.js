#!/usr/bin/env node
// Ondata 3 — SC3 test suite:
//   B6 : tools/retrieval-budget.js — selezione deterministica a budget fisso (funzione pura,
//        CLI select --file|--stdin, limiti per kind, tie-break, char-budget first-fit,
//        fail-closed su input malformato).
//   F6 : tools/model-routing.js — routing modelli per ruolo: plan DRY-RUN a zero scritture,
//        render confinato all'outdir (deterministico, guardie anti-traversal/~/.dsh),
//        apply con --yes esplicito + backup preventivo.
//   E12: TOOL_REQUIRES_KEY — gating env-key in run.js (union registry+env, blocco anche del
//        dry-run, env malformata FATALE) e preflight in tool-plane.js (--require-key / --check-keys).
// Tutto offline: fixture in mkdtemp, env override (SCOPE_JSON/TOOL_REGISTRY/RUN_AUDIT_FILE/
// TOOL_PLANE_OUT/MODEL_ROUTING_FILE/AGENT_PRESETS_DIR/HOME).
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
const RETRIEVAL = path.join(WS, 'tools', 'retrieval-budget.js');
const ROUTING = path.join(WS, 'tools', 'model-routing.js');
const RUN = path.join(WS, 'tools', 'run.js');
const PLANE = path.join(WS, 'tools', 'tool-plane.js');
const runLib = require(RUN);

function cli(file, args, env) {
  return spawnSync(process.execPath, [file, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 30000 });
}

// ---- fixtures condivise ---------------------------------------------------------------
function makeItems(n) {
  const items = [];
  for (let i = 0; i < n; i++) {
    items.push({
      id: 'i' + String(i).padStart(3, '0'),
      kind: i % 2 === 0 ? 'observation' : 'diagnostic',
      score: 100 - i,
      ts: '2026-08-26T0' + String(1 + (i % 9)) + ':00:00.000Z',
      text: 'osservazione/diagnostica ' + i + ' ' + 'x'.repeat(20),
    });
  }
  return items;
}

async function main() {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'sc3-'));
  const SCOPE = path.join(T, 'scope.json');
  fs.writeFileSync(SCOPE, JSON.stringify({ targets: ['target.example'], exclusions: [] }));
  const REG = path.join(T, 'reg.json');
  fs.writeFileSync(REG, JSON.stringify({
    fakebin: { risk_tier: 'read', rate_class: 'normal', read_only: true, requires_key: ['FAKE_API_KEY'] },
    plainbin: { risk_tier: 'read', rate_class: 'normal', read_only: true },
  }));
  const BASE_ENV = { SCOPE_JSON: SCOPE, TOOL_REGISTRY: REG, RUN_AUDIT_FILE: path.join(T, 'audit.jsonl'), TOOL_PLANE_OUT: path.join(T, 'plane.json') };

  // ================================================================ B6 retrieval-budget
  console.log('B6 — retrieval-budget: CLI select');
  const itemsFile = path.join(T, 'items.json');
  const items = makeItems(20); // 10 observation + 10 diagnostic, score 100..81
  fs.writeFileSync(itemsFile, JSON.stringify(items));
  ok('select --file: exit 0, conteggi coerenti con limiti default (6 obs + 4 diag)', () => {
    const r = cli(RETRIEVAL, ['select', '--file', itemsFile]);
    assert.strictEqual(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout);
    assert.strictEqual(o.counts.selected.observation, 6);
    assert.strictEqual(o.counts.selected.diagnostic, 4);
    assert.strictEqual(o.counts.selected.total, 10);
    assert.strictEqual(o.counts.dropped.kind_limit, 10);
    assert.strictEqual(o.selected.length, 10);
    assert.strictEqual(o.dropped.filter((d) => d.reason === 'kind_limit').length, 10);
    // ordine globale: score desc → ts asc → id asc
    const scores = o.selected.map((s) => s.score);
    assert.deepStrictEqual(scores, [...scores].sort((a, b) => b - a));
  });
  ok('select --stdin (piped): stessa selezione, byte-identica al --file', () => {
    const viaFile = cli(RETRIEVAL, ['select', '--file', itemsFile]).stdout;
    const viaStdin = spawnSync(process.execPath, [RETRIEVAL, 'select', '--stdin', '--obs-limit', '6', '--diag-limit', '4'], { encoding: 'utf8', input: fs.readFileSync(itemsFile, 'utf8'), timeout: 30000 }).stdout;
    assert.strictEqual(viaStdin, viaFile);
  });
  await okAsync('determinismo: 100 run identiche (byte-identiche)', async () => {
    const first = cli(RETRIEVAL, ['select', '--file', itemsFile]).stdout;
    for (let i = 0; i < 99; i++) {
      const r = cli(RETRIEVAL, ['select', '--file', itemsFile]);
      assert.strictEqual(r.status, 0);
      assert.strictEqual(r.stdout, first, 'run ' + i + ' divergente');
    }
  });
  ok('tie-break stabile: stesso score+ts → id ASC (code-unit)', () => {
    const f = path.join(T, 'tie.json');
    fs.writeFileSync(f, JSON.stringify([
      { id: 'zeta', kind: 'observation', score: 50, ts: '2026-08-26T10:00:00.000Z' },
      { id: 'alpha', kind: 'observation', score: 50, ts: '2026-08-26T10:00:00.000Z' },
    ]));
    const r = cli(RETRIEVAL, ['select', '--file', f]);
    assert.strictEqual(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout);
    assert.deepStrictEqual(o.selected.map((s) => s.id), ['alpha', 'zeta'], 'id ASC nonostante input zeta-first');
  });
  ok('char-budget: first-fit nell\'ordine globale con drop motivato char_budget', () => {
    const f = path.join(T, 'cb.json');
    // ogni item ha text di ~30 byte; budget per solo 2 item
    fs.writeFileSync(f, JSON.stringify(makeItems(4)));
    const r = cli(RETRIEVAL, ['select', '--file', f, '--char-budget', '70']);
    assert.strictEqual(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout);
    assert.ok(o.selected.length >= 1 && o.selected.length <= 2, 'budget 70 byte deve contenere 1-2 item, selezionati: ' + o.selected.length);
    assert.ok(o.dropped.some((d) => d.reason === 'char_budget'), 'deve esistere almeno un drop char_budget');
    assert.ok(o.chars <= 70, 'chars accumulati non possono superare il budget');
  });
  ok('input malformato → exit 1 con messaggio che cita id/indice; nessun output di selezione', () => {
    const f = path.join(T, 'bad.json');
    fs.writeFileSync(f, JSON.stringify([{ id: 'a', kind: 'bogus', score: 1, ts: '2026-08-26T00:00:00Z' }]));
    let r = cli(RETRIEVAL, ['select', '--file', f]);
    assert.strictEqual(r.status, 1, r.stdout);
    assert.ok(r.stderr.includes('kind'), r.stderr);
    // JSON malformato
    fs.writeFileSync(f, '{not json');
    r = cli(RETRIEVAL, ['select', '--file', f]);
    assert.strictEqual(r.status, 1);
    // id duplicato
    fs.writeFileSync(f, JSON.stringify([
      { id: 'a', kind: 'observation', score: 1, ts: '2026-08-26T00:00:00Z' },
      { id: 'a', kind: 'observation', score: 2, ts: '2026-08-26T00:00:00Z' },
    ]));
    r = cli(RETRIEVAL, ['select', '--file', f]);
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes('DUPLICATO'), r.stderr);
  });
  ok('uso errato → exit 2 (nessuna sorgente; flag numerica malformata)', () => {
    let r = cli(RETRIEVAL, ['select']);
    assert.strictEqual(r.status, 2, r.stdout);
    r = cli(RETRIEVAL, ['select', '--file', itemsFile, '--obs-limit', 'abc']);
    assert.strictEqual(r.status, 2, r.stdout);
  });
  ok('libreria select(): pura, input non mutato, input vuoto/non-array rifiutati', () => {
    const lib = require(RETRIEVAL);
    const before = JSON.stringify(items);
    const a = lib.select(items, {});
    const b = lib.select(items, {});
    assert.strictEqual(JSON.stringify(a), JSON.stringify(b), 'funzione pura: stesso input → stesso output');
    assert.strictEqual(JSON.stringify(items), before, 'input non mutato (nessun riferimento condiviso nei selected)');
    a.selected[0].text = 'MUTATO';
    assert.notStrictEqual(items[0].text, 'MUTATO', 'le copie non devono condividere oggetti con l\'input');
    assert.throws(() => lib.select([], {}), /vuoto/);
    assert.throws(() => lib.select('nope', {}), /ARRAY/);
  });

  // ================================================================ F6 model-routing
  console.log('F6 — model-routing: plan dry-run a zero scritture');
  const PRESETS = path.join(T, 'presets');
  const modeDir = path.join(PRESETS, 'pentest');
  fs.mkdirSync(path.join(modeDir, 'skills'), { recursive: true });
  fs.writeFileSync(path.join(modeDir, 'agent.cordis.yml'), 'preset: pentest\n');
  fs.writeFileSync(path.join(modeDir, 'preset.yml'), 'mode: pentest\n');
  const F6_ENV = { AGENT_PRESETS_DIR: PRESETS, HOME: path.join(T, 'home') };
  ok('plan: ZERO scritture (nessun sidecar, nessuna dir nuova), azioni create', () => {
    const before = fs.readdirSync(PRESETS).sort();
    const r = cli(ROUTING, ['plan'], F6_ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes('pentest') && r.stdout.includes('create'), r.stdout);
    assert.deepStrictEqual(fs.readdirSync(PRESETS).sort(), before, 'plan non deve creare nulla');
    assert.ok(!fs.existsSync(path.join(modeDir, 'model-route.json')), 'nessun sidecar scritto');
  });
  ok('plan su root assente: messaggio dedicato, exit 0, nessuna scrittura', () => {
    const r = cli(ROUTING, ['plan'], { ...F6_ENV, AGENT_PRESETS_DIR: path.join(T, 'no-root') });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes('root assente'), r.stdout);
  });
  ok('render --out: confinato all\'outdir, proposte DETERMINISTICHE (2 run byte-identiche)', () => {
    const out1 = path.join(T, 'out1');
    const out2 = path.join(T, 'out2');
    const r1 = cli(ROUTING, ['render', '--out', out1], F6_ENV);
    const r2 = cli(ROUTING, ['render', '--out', out2], F6_ENV);
    assert.strictEqual(r1.status, 0, r1.stderr);
    assert.strictEqual(r2.status, 0, r2.stderr);
    const f1 = path.join(out1, 'pentest.model-route.json');
    const f2 = path.join(out2, 'pentest.model-route.json');
    assert.ok(fs.existsSync(f1));
    assert.strictEqual(fs.readFileSync(f1, 'utf8'), fs.readFileSync(f2, 'utf8'), 'render deterministico (nessun timestamp)');
    assert.ok(!fs.existsSync(path.join(modeDir, 'model-route.json')), 'render non tocca i preset');
    const prop = JSON.parse(fs.readFileSync(f1, 'utf8'));
    assert.strictEqual(prop.version, 1);
    assert.ok(prop.map_sha256 && /^[0-9a-f]{64}$/.test(prop.map_sha256));
    assert.ok(prop.phases_resolved.planning.model, 'phases risolte con modello');
  });
  ok('render RIFIUTA outdir == HOME / dentro ~/.dsh / dentro AGENT_PRESETS_DIR / radice (zero scritture)', () => {
    const home = path.join(T, 'home');
    fs.mkdirSync(home, { recursive: true });
    const dsh = path.join(home, '.dsh');
    fs.mkdirSync(dsh, { recursive: true });
    for (const bad of [home, path.join(dsh, 'x'), PRESETS, path.join(PRESETS, 'y'), '/']) {
      const r = cli(ROUTING, ['render', '--out', bad], F6_ENV);
      assert.strictEqual(r.status, 1, 'atteso rifiuto per --out ' + bad + ' (exit=' + r.status + ') ' + r.stdout.slice(0, 200));
      assert.ok(!fs.existsSync(path.join(bad, 'pentest.model-route.json')), 'nessuna proposta scritta in ' + bad);
    }
  });
  ok('render RIFIUTA outdir che risolve (via symlink antenato) dentro ~/.dsh', () => {
    const home = path.join(T, 'home2');
    fs.mkdirSync(path.join(home, '.dsh'), { recursive: true });
    const link = path.join(T, 'link-to-dsh');
    fs.symlinkSync(path.join(home, '.dsh'), link);
    const r = cli(ROUTING, ['render', '--out', link], { ...F6_ENV, HOME: home });
    assert.strictEqual(r.status, 1, r.stdout.slice(0, 200));
  });
  ok('apply SENZA --yes: rifiuto exit≠0 e ZERO scritture', () => {
    const r = cli(ROUTING, ['apply'], F6_ENV);
    assert.notStrictEqual(r.status, 0);
    assert.ok(!fs.existsSync(path.join(modeDir, 'model-route.json')));
  });
  ok('apply --yes: sidecar scritti + backup preventivo con SHA256SUMS; plan poi dice unchanged', () => {
    // sidecar pre-esistente (simula un apply precedente) da preservare in backup
    fs.writeFileSync(path.join(modeDir, 'model-route.json'), '{"legacy":true}\n');
    const r = cli(ROUTING, ['apply', '--yes'], F6_ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    const sc = JSON.parse(fs.readFileSync(path.join(modeDir, 'model-route.json'), 'utf8'));
    assert.strictEqual(sc.generated_by, 'tools/model-routing.js');
    assert.ok(sc.applied_at, 'apply aggiunge applied_at');
    const backups = fs.readdirSync(path.join(PRESETS, '.backup-model-routing'));
    assert.strictEqual(backups.length, 1);
    const bk = path.join(PRESETS, '.backup-model-routing', backups[0]);
    const sums = fs.readFileSync(path.join(bk, 'SHA256SUMS'), 'utf8');
    assert.ok(sums.includes('pentest.model-route.json'), 'SHA256SUMS copre il sidecar precedente');
    const plan = cli(ROUTING, ['plan'], F6_ENV);
    assert.ok(plan.stdout.includes('unchanged'), 'dopo apply il plan deve dire unchanged:\n' + plan.stdout);
  });
  ok('mappa invalida: rifiuto fail-closed con TUTTI gli errori (exit 1); JSON rotto = exit 2; flag ignota = exit 2', () => {
    const bad = path.join(T, 'bad-map.json');
    fs.writeFileSync(bad, JSON.stringify({ version: 1, roles: {}, phases: { x: 'ghost' } }));
    let r = cli(ROUTING, ['plan'], { ...F6_ENV, MODEL_ROUTING_FILE: bad });
    assert.strictEqual(r.status, 1, r.stdout);
    assert.ok(r.stderr.includes('roles') && r.stderr.includes('ghost'), r.stderr);
    fs.writeFileSync(bad, '{oops');
    r = cli(ROUTING, ['plan'], { ...F6_ENV, MODEL_ROUTING_FILE: bad });
    assert.strictEqual(r.status, 1, 'JSON malformato = mappa INVALIDA (exit 1, non io-illeggibile)'); // parse -> 1 (spec: "mappa invalida"); io illeggibile -> 2
    r = cli(ROUTING, ['--nope'], F6_ENV);
    assert.strictEqual(r.status, 2, r.stdout);
  });

  // ================================================================ E12 run.js
  console.log('E12 — TOOL_REQUIRES_KEY: gating in run.js');
  ok('validateRegistry: accetta requires_key valido; rifiuta non-array (registry-check exit≠0)', () => {
    const good = { b: { risk_tier: 'read', rate_class: 'normal', read_only: true, requires_key: ['K1', 'K2'] } };
    assert.deepStrictEqual(runLib.validateRegistry(good), []);
    const bad = { b: { risk_tier: 'read', rate_class: 'normal', read_only: true, requires_key: 'K1' } };
    const errs = runLib.validateRegistry(bad);
    assert.ok(errs.length === 1 && errs[0].includes('requires_key'), JSON.stringify(errs));
  });
  ok('registry reale: --registry-check resta ok:true (requires_key documentato, nessun requisito reale)', () => {
    const r = cli(RUN, ['--registry-check']);
    const o = JSON.parse(r.stdout);
    assert.strictEqual(o.ok, true, r.stdout);
    assert.strictEqual(o.bins, 28);
  });
  ok('chiave mancante → exit 1, audit {gate:tool_requires_key, missing_keys}, classe key_missing (anche dry-run)', () => {
    const audit = path.join(T, 'audit-e12.jsonl');
    const r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], { ...BASE_ENV, RUN_AUDIT_FILE: audit });
    assert.strictEqual(r.status, 1, r.stdout + r.stderr);
    const line = JSON.parse(fs.readFileSync(audit, 'utf8').trim().split('\n').pop());
    assert.strictEqual(line.gate, 'tool_requires_key');
    assert.deepStrictEqual(line.missing_keys, ['FAKE_API_KEY']);
    assert.strictEqual(line.error_class, 'key_missing');
    assert.strictEqual(line.recovery.action, 'configure_api_key');
    assert.ok(r.stderr.includes('FAKE_API_KEY'), r.stderr);
  });
  ok('chiave presente → dry-run ok (exit 0); blocco valido SOLO se manca davvero', () => {
    const r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], { ...BASE_ENV, FAKE_API_KEY: 'x' });
    assert.strictEqual(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout);
    assert.strictEqual(o.dry_run, true);
  });
  ok('union ADDITIVA: TOOL_REQUIRES_KEY aggiunge (non rimuove) requisiti', () => {
    // env aggiunge EXTRA_KEY al bin: ora servono ENTRAMBE
    let r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], { ...BASE_ENV, TOOL_REQUIRES_KEY: 'fakebin=EXTRA_KEY' });
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes('FAKE_API_KEY') && r.stderr.includes('EXTRA_KEY'), r.stderr);
    r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], { ...BASE_ENV, TOOL_REQUIRES_KEY: 'fakebin=EXTRA_KEY', FAKE_API_KEY: '1', EXTRA_KEY: '2' });
    assert.strictEqual(r.status, 0, r.stderr);
  });
  ok('env TOOL_REQUIRES_KEY MALFORMATA → FATALE exit 2, mai fallback silenzioso', () => {
    let r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], { ...BASE_ENV, TOOL_REQUIRES_KEY: 'noequals' });
    assert.strictEqual(r.status, 2, r.stdout);
    assert.ok(r.stderr.includes('TOOL_REQUIRES_KEY'), r.stderr);
    r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], { ...BASE_ENV, TOOL_REQUIRES_KEY: 'fakebin=' });
    assert.strictEqual(r.status, 2, r.stdout);
  });
  ok('bin SENZA requisiti (registry o env) non viene bloccato da TOOL_REQUIRES_KEY di altri bin', () => {
    const r = cli(RUN, ['--dry-run', 'plainbin', 'http://target.example/'], { ...BASE_ENV, TOOL_REQUIRES_KEY: 'otherbin=SOME_KEY' });
    assert.strictEqual(r.status, 0, r.stderr);
  });

  // ================================================================ E12 tool-plane
  console.log('E12 — tool-plane: --check-keys / --require-key');
  ok('--check-keys: report JSON con presente/mancante; exit 1 se manca, 0 se tutto presente', () => {
    let r = cli(PLANE, ['--check-keys', '--json'], BASE_ENV);
    assert.strictEqual(r.status, 1, r.stdout);
    let o = JSON.parse(r.stdout);
    assert.deepStrictEqual(o.requirements.fakebin.missing, ['FAKE_API_KEY']);
    r = cli(PLANE, ['--check-keys', '--json'], { ...BASE_ENV, FAKE_API_KEY: 'x' });
    assert.strictEqual(r.status, 0, r.stdout);
    o = JSON.parse(r.stdout);
    assert.deepStrictEqual(o.requirements.fakebin.present, ['FAKE_API_KEY']);
    assert.deepStrictEqual(o.requirements.fakebin.missing, []);
  });
  ok('--require-key: exit 1 elencando le mancanti; exit 0 se presenti', () => {
    let r = cli(PLANE, ['--require-key', 'fakebin'], BASE_ENV);
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes('FAKE_API_KEY'), r.stderr);
    r = cli(PLANE, ['--require-key', 'fakebin'], { ...BASE_ENV, FAKE_API_KEY: 'x' });
    assert.strictEqual(r.status, 0, r.stderr);
  });
  ok('--require-key con =ENV esplicito (union additiva): richiede anche quella env', () => {
    const r = cli(PLANE, ['--require-key', 'fakebin=OTHER_KEY'], BASE_ENV);
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes('OTHER_KEY'), r.stderr);
    const r2 = cli(PLANE, ['--require-key', 'fakebin=OTHER_KEY'], { ...BASE_ENV, OTHER_KEY: '1' });
    assert.strictEqual(r2.status, 0, r2.stderr);
  });
  ok('--require-key bin senza requisito noto: warning non bloccante (exit 0)', () => {
    const r = cli(PLANE, ['--require-key', 'nosuchbin'], BASE_ENV);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(r.stderr.includes('nessun requisito chiave noto'), r.stderr);
  });
  ok('env TOOL_REQUIRES_KEY malformata in tool-plane → FATALE exit 2', () => {
    const r = cli(PLANE, ['--check-keys'], { ...BASE_ENV, TOOL_REQUIRES_KEY: 'nope' });
    assert.strictEqual(r.status, 2, r.stdout);
    assert.ok(r.stderr.includes('TOOL_REQUIRES_KEY'), r.stderr);
  });

  console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
  fs.rmSync(T, { recursive: true, force: true });
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
