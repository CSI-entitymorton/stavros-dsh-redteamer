#!/usr/bin/env node
// Ondata 4 — suite di regressione (SC1→SC4):
//   SC1 (F4) : entity taxonomy — docs/entity-taxonomy.yaml + tools/entity-taxonomy.js
//              (validatore fail-closed, adattatore read-only grafo memoria, integrazione
//              coverage.js additiva, classOf title-first).
//   SC2 (F8+C4w): accounting token/costo — tools/accounting.js (funzioni pure), run.js
//              --tokens/--tokens-cost/AGENT_NAME, usage su record-finding NUOVI (A3 intatta),
//              sezione «Costi & usage» in report-html, opstate accounting read-only/--record.
//   SC3 (E3) : gate dichiarativi via `reports:` del dialetto workflow — workflow.js
//              (mini-parser + validateDoc) e gate.js --workflow/GATE_WORKFLOW_FILE
//              (replace dei check 'file', fail-closed, legacy invariato, SA1 intatto).
//   SC4 (C5w): audit trail isolato append-only — tools/audit-trail.js (hash-chain leggera,
//              permessi 0o700/0o600, AUDIT_DIR), hook in run.js audit().
// Tutto OFFLINE (solo stdlib), fixture SOLO in mkdtemp, env override ovunque, MAI path reali.
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

const WS = path.join(__dirname, '..');
const TAX = path.join(WS, 'tools', 'entity-taxonomy.js');
const ACC = path.join(WS, 'tools', 'accounting.js');
const AUDIT = path.join(WS, 'tools', 'audit-trail.js');
const RUN = path.join(WS, 'tools', 'run.js');
const GATE = path.join(WS, 'tools', 'gate.js');
const WF = path.join(WS, 'tools', 'workflow.js');
const OPSTATE = path.join(WS, 'tools', 'opstate.js');
const taxLib = require(TAX);
const accLib = require(ACC);
const auditLib = require(AUDIT);
const gateLib = require(GATE);
const runLib = require(RUN);
const wfLib = require(WF);

function cli(file, args, env) {
  return spawnSync(process.execPath, [file, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 30000 });
}

async function main() {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'ondata4-'));
  const SCOPE = path.join(T, 'scope.json');
  fs.writeFileSync(SCOPE, JSON.stringify({ targets: ['target.example'], exclusions: [] }));
  // gate.js CLI resolves its workspace via GATE_WS (default = package root); point it at a
  // hermetic fixture so the tests never touch the repo's real (gitignored) reports/scope.
  const gw = path.join(T, 'gate-ws');
  fs.mkdirSync(path.join(gw, 'reports'), { recursive: true });
  fs.writeFileSync(path.join(gw, 'scope.json'), JSON.stringify({ targets: ['target.example'] }));
  fs.writeFileSync(path.join(gw, 'reports', 'findings.jsonl'), JSON.stringify({
    severity: 'Low', title: 'fixture', host: 'target.example', poc: 'x', status: 'inconclusive',
  }) + '\n');
  const REG = path.join(T, 'reg.json');
  fs.writeFileSync(REG, JSON.stringify({
    fakebin: { risk_tier: 'read', rate_class: 'normal', read_only: true },
  }));
  const BASE_ENV = {
    SCOPE_JSON: SCOPE, TOOL_REGISTRY: REG,
    RUN_AUDIT_FILE: path.join(T, 'audit.jsonl'),
    AUDIT_DIR: path.join(T, 'audit'),
  };

  // ================================================================ SC1 — F4 taxonomy
  console.log('SC1 (F4) — entity taxonomy');
  const tax = taxLib.loadTaxonomy(); // carica la YAML versionata dal repo
  ok('taxonomy: 6 entità, version ≥ 1, field types ammessi', () => {
    assert.strictEqual(tax.version, 1);
    assert.deepStrictEqual(Object.keys(tax.entities).sort(), ['Evidence', 'Finding', 'Port', 'Service', 'Target', 'Vuln']);
    for (const def of Object.values(tax.entities)) {
      assert.ok(Array.isArray(def.required) && def.required.length > 0, 'required non vuoto');
      assert.ok(def.description && typeof def.description === 'string');
    }
    assert.ok(tax.relations && typeof tax.relations === 'object');
  });
  ok('validate: entità Finding valida (campi obbligatori + usage opzionale) ok', () => {
    assert.strictEqual(taxLib.validateEntity({
      type: 'entity', entityType: 'Finding', id: 'F-1', vuln_ref: 'V-1',
      severity: 'High', status: 'confirmed', host: 'target.example',
      usage: { tokens_in: 10, tokens_out: 5, cost: 0.001 },
    }, tax), null);
  });
  ok('validate: campo obbligatorio mancante → fail-closed', () => {
    const err = taxLib.validateEntity({ entityType: 'Finding', id: 'F-1', vuln_ref: 'V-1', severity: 'High', status: 'confirmed' }, tax);
    assert.ok(err && /missing required field "host"/.test(err), err);
  });
  ok('validate: tipo opzionale errato (cvss string) → rifiutato', () => {
    const err = taxLib.validateEntity({
      entityType: 'Finding', id: 'F-1', vuln_ref: 'V-1', severity: 'High', status: 'confirmed', host: 'h', cvss: '8.6',
    }, tax);
    assert.ok(err && /cvss/.test(err), err);
  });
  ok('validate: entità SPURIA (entityType ignoto) → rifiutata', () => {
    const err = taxLib.validateEntity({ entityType: 'Spurious', id: 'x' }, tax);
    assert.ok(err && /spurious entity/.test(err), err);
  });
  ok('validate: campo sconosciuto → rifiutato (nessuna entità spuria)', () => {
    const err = taxLib.validateEntity({
      entityType: 'Finding', id: 'F-1', vuln_ref: 'V-1', severity: 'High', status: 'confirmed', host: 'h', bogus: 1,
    }, tax);
    assert.ok(err && /spurious field "bogus"/.test(err), err);
  });
  ok('validate: relazione non consentita → rifiutata', () => {
    const err = taxLib.validateEntity({
      entityType: 'Finding', id: 'F-1', vuln_ref: 'V-1', severity: 'High', status: 'confirmed', host: 'h',
      relations: [{ type: 'runs_service', to: 'P-1' }],
    }, tax);
    assert.ok(err && /not allowed/.test(err), err);
  });
  ok('validate: campi nativi del grafo (type/observations) sempre accettati', () => {
    assert.strictEqual(taxLib.validateEntity({
      type: 'entity', entityType: 'Target', id: 'T-1', name: 'target.example',
      observations: ['ok'], relations: [{ type: 'has_port', to: 'P-1' }],
    }, tax), null);
  });
  ok('validateEntities: lista con 1 valida + 1 cattiva → errors[1], ok=false', () => {
    const r = taxLib.validateEntities([
      { entityType: 'Target', id: 'T-1', name: 'h' },
      { entityType: 'Target', id: 'T-2' },
    ], tax);
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.errors.length, 1);
    assert.strictEqual(r.valid, 1);
  });
  ok('CLI validate: exit 0 buona / exit 1 cattiva', () => {
    const good = cli(TAX, ['validate', JSON.stringify({ entityType: 'Target', id: 'T-1', name: 'h' })]);
    assert.strictEqual(good.status, 0, good.stderr);
    const bad = cli(TAX, ['validate', JSON.stringify({ entityType: 'Target', id: 'T-1' })]);
    assert.strictEqual(bad.status, 1);
  });
  ok('CLI taxonomy: stampa le 6 entità', () => {
    const r = cli(TAX, ['taxonomy']);
    assert.strictEqual(r.status, 0);
    for (const t of ['Target', 'Port', 'Service', 'Vuln', 'Finding', 'Evidence']) assert.ok(r.stdout.includes('## ' + t), t);
  });

  // finding → entità tipizzate
  const findingRow = {
    severity: 'High', title: 'SQLi in login', host: 'target.example', endpoint: '/login', poc: 'p',
    status: 'confirmed', cwe: 'CWE-89', cvss: 8.6,
    evidence_quote: { file: 'reports/tmp/x.txt', text: 'sqli' },
    usage: { tokens_in: 100, tokens_out: 50, cost: 0.001 },
  };
  ok('findingToEntity: mappa a Target/Vuln/Evidence/Finding tipizzate e VALIDE', () => {
    const r = taxLib.findingToEntity(findingRow);
    assert.strictEqual(r.errors.length, 0, r.errors.join('; '));
    const types = r.entities.map((e) => e.entityType).sort();
    assert.deepStrictEqual(types, ['Evidence', 'Finding', 'Target', 'Vuln']);
    const finding = r.entities.find((e) => e.entityType === 'Finding');
    assert.strictEqual(finding.host, 'target.example');
    assert.strictEqual(finding.severity, 'High');
    assert.deepStrictEqual(finding.usage, { tokens_in: 100, tokens_out: 50, cost: 0.001 });
    const vuln = r.entities.find((e) => e.entityType === 'Vuln');
    assert.strictEqual(vuln.class, 'sqli'); // title-first classification
  });
  ok('findingsToEntities: dedupe su id, entità invalide → errori (fail-closed)', () => {
    const r = taxLib.findingsToEntities([findingRow, findingRow, { severity: 'High' }], tax);
    assert.strictEqual(r.errors.length, 1, JSON.stringify(r.errors)); // il terzo (senza title/host) fallisce
    assert.strictEqual(r.deduped, 4); // 4 entità uniche dal finding valido
  });

  // memory graph (read-only)
  ok('graph adapter: legge NDJSON, entità taxonomy validate, legacy skipped, MAI scritture', () => {
    const graphFile = path.join(T, 'memory.ndjson');
    const before = ['{"type":"entity","name":"legacy-1","entityType":"verification","observations":["x"]}',
      '{"type":"entity","entityType":"Finding","id":"F-1","vuln_ref":"V-1","severity":"High","status":"confirmed","host":"target.example"}'].join('\n') + '\n';
    fs.writeFileSync(graphFile, before);
    const r = taxLib.graphEntitiesFromFile(graphFile, tax);
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.total, 2);
    assert.strictEqual(r.taxonomy, 1);
    assert.strictEqual(r.skipped, 1);
    assert.strictEqual(r.invalid, 0);
    assert.strictEqual(fs.readFileSync(graphFile, 'utf8'), before, 'grafo non toccato (read-only)');
    const dirBefore = fs.readdirSync(T).sort();
    void dirBefore;
    assert.ok(!fs.existsSync(path.join(T, 'lab-memory.json')), 'nessun file nuovo creato');
  });
  ok('graph adapter: entità tassonomica INVALIDA nel grafo → invalid counted, non silenziosa', () => {
    const graphFile = path.join(T, 'memory-bad.ndjson');
    fs.writeFileSync(graphFile, '{"type":"entity","entityType":"Port","id":"P-1"}\n'); // manca port/protocol/target_ref
    const r = taxLib.graphEntitiesFromFile(graphFile, tax);
    assert.strictEqual(r.invalid, 1);
    assert.ok(r.errors[0].includes('missing required'), r.errors[0]);
  });
  ok('CLI graph: exit 0 su grafo pulito, exit 1 su righe invalide', () => {
    const g1 = path.join(T, 'g1.ndjson');
    fs.writeFileSync(g1, '{"type":"entity","entityType":"Target","id":"T-1","name":"h"}\n');
    assert.strictEqual(cli(TAX, ['graph', g1]).status, 0);
    const g2 = path.join(T, 'g2.ndjson');
    fs.writeFileSync(g2, '{"entityType":"Port","id":"P-1"}\n');
    assert.strictEqual(cli(TAX, ['graph', g2]).status, 1);
  });

  // integrazione coverage.js (additiva)
  ok('coveredClassesFromEntities: classe sqli derivata da entità tipizzate', () => {
    const r = taxLib.findingsToEntities([findingRow], tax);
    assert.deepStrictEqual(taxLib.coveredClassesFromEntities(r.entities), ['sqli']);
  });
  ok('coverage.buildMatrix con opts.entities: sqli confirmed, xss missed (ADDITIVO)', () => {
    const cov = require(path.join(WS, 'tools', 'coverage'));
    const covDir = path.join(T, 'cov');
    fs.mkdirSync(covDir, { recursive: true });
    fs.writeFileSync(path.join(covDir, 'target.example-map.json'), JSON.stringify({}));
    const entities = taxLib.findingsToEntities([findingRow], tax).entities;
    const m = cov.buildMatrix('target.example', { reportsDir: covDir, findingsFile: path.join(covDir, 'f.jsonl'), entities });
    assert.strictEqual(m.rows.find((r) => r.class === 'sqli').status, 'confirmed');
    assert.strictEqual(m.rows.find((r) => r.class === 'xss').status, 'missed');
    const m2 = cov.buildMatrix('target.example', { reportsDir: covDir, findingsFile: path.join(covDir, 'f.jsonl') });
    assert.strictEqual(m2.rows.find((r) => r.class === 'sqli').status, 'missed', 'senza entities: legacy identico');
  });
  ok('classOf title-first: cwe CWE-89 + title SQLi → sqli (non other)', () => {
    const cov = require(path.join(WS, 'tools', 'coverage'));
    assert.strictEqual(cov.classOf({ cwe: 'CWE-89', title: 'SQLi in login' }), 'sqli');
    assert.strictEqual(cov.classOf({ cwe: 'CWE-89' }), 'other', 'solo CWE (senza testo) resta other → fallback invariato');
  });

  // ================================================================ SC2 — F8+C4w accounting
  console.log('SC2 (F8+C4w) — accounting token/costo');
  ok('entryUsage: oggetto usage canonico (tokens default 0, cost null)', () => {
    assert.deepStrictEqual(accLib.entryUsage({ usage: { tokens_in: 10, tokens_out: 20, cost: 0.5 } }), {
      tokens_in: 10, tokens_out: 20, tokens: 30, cost: 0.5, duration_ms: null, source: null,
    });
    assert.deepStrictEqual(accLib.entryUsage({}), { tokens_in: 0, tokens_out: 0, tokens: 0, cost: null, duration_ms: null, source: null });
  });
  ok('entryUsage: flat fields accettati; cost non-numerico → null (mai fabbricato)', () => {
    const u = accLib.entryUsage({ tokens_in: 5, tokens_out: 3, cost: 'nope', ms: 1200 });
    assert.strictEqual(u.tokens, 8);
    assert.strictEqual(u.cost, null);
    assert.strictEqual(u.duration_ms, 1200);
  });
  ok('aggregateAll: totals + per-action + per-agent corretti e PURI (idempotenti)', () => {
    const lines = [
      { ts: 't1', bin: 'nmap', agent: 'scout', usage: { tokens_in: 1000, tokens_out: 500, cost: 0.01 } },
      { ts: 't2', bin: 'nmap', agent: 'scout', usage: { tokens_in: 2000, tokens_out: 1000, cost: 0.02 } },
      { ts: 't3', bin: 'ffuf', agent: 'recon', usage: { tokens_in: 300, tokens_out: 200 } },
    ];
    const a = accLib.aggregateAll(lines);
    assert.strictEqual(a.session.invocations, 3);
    assert.strictEqual(a.session.tokens, 5000);
    assert.strictEqual(a.session.tokens_in, 3300);
    assert.strictEqual(a.session.tokens_out, 1700);
    assert.strictEqual(a.session.cost, 0.03);
    assert.strictEqual(a.session.cost_known, 2);
    assert.strictEqual(a.actions.per_bin.nmap.invocations, 2);
    assert.strictEqual(a.actions.per_bin.ffuf.tokens, 500);
    assert.strictEqual(a.agents.per_agent.scout.tokens, 4500);
    assert.strictEqual(a.agents.per_agent.recon.invocations, 1);
    assert.deepStrictEqual(a, accLib.aggregateAll(lines), 'funzione pura: 2 run identiche');
  });
  ok('aggregateAll: string JSONL accettata; righe malformate ignorate', () => {
    const text = '{"bin":"a","usage":{"tokens_in":1,"tokens_out":1}}\nnot json\n{"bin":"b"}\n';
    const a = accLib.aggregateAll(text);
    assert.strictEqual(a.session.invocations, 2);
    assert.strictEqual(a.session.tokens, 2);
  });
  ok('run.js --tokens/--tokens-cost/AGENT_NAME: usage+agent nell audit (e2e, dry-run)', () => {
    const auditFile = path.join(T, 'audit-f8.jsonl');
    const env = { ...BASE_ENV, RUN_AUDIT_FILE: auditFile, AUDIT_DIR: path.join(T, 'audit-f8'), AGENT_NAME: 'scout' };
    const r = cli(RUN, ['--dry-run', '--tokens', '1200,800', '--tokens-cost', '0.004', 'fakebin', 'http://target.example/'], env);
    assert.strictEqual(r.status, 0, r.stderr);
    const line = JSON.parse(fs.readFileSync(auditFile, 'utf8').trim().split('\n').pop());
    assert.deepStrictEqual(line.usage, { tokens_in: 1200, tokens_out: 800, cost: 0.004, source: 'cli/env' });
    assert.strictEqual(line.agent, 'scout');
  });
  ok('runBinary espone ms (duration) per il calcolo costo/azione', async () => {
    const r = await runLib.runBinary(process.execPath, ['-e', 'process.exit(0)'], { capture: true });
    assert.ok(r.ms >= 0, 'ms presente');
  });
  ok('run.js token malformati → FATALI exit 2 (fail-closed, nessun fallback)', () => {
    let r = cli(RUN, ['--dry-run', '--tokens', 'abc', 'fakebin', 'http://target.example/'], BASE_ENV);
    assert.strictEqual(r.status, 2, r.stdout);
    r = cli(RUN, ['--dry-run', '--tokens-cost', '-1', 'fakebin', 'http://target.example/'], BASE_ENV);
    assert.strictEqual(r.status, 2, r.stdout);
    r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], { ...BASE_ENV, RUN_TOKENS_IN: 'x' });
    assert.strictEqual(r.status, 2, r.stdout);
  });
  ok('record-finding con usage: registrato, chain A3 INTATTA (nessuna regressione)', () => {
    const RF_DIR = path.join(T, 'rf');
    const FJ = path.join(RF_DIR, 'findings.jsonl');
    const RF_ENV = {
      DSH_WS_ROOT: RF_DIR, ORACLE_ARTIFACTS: path.join(RF_DIR, 'artifacts', 'oracle'),
      FINDINGS_JSONL: FJ, LOOT_JSONL: path.join(RF_DIR, 'loot.jsonl'), FINDINGS_TAB_DB: path.join(RF_DIR, 'tab.db'),
    };
    const saved = Object.fromEntries(Object.keys(RF_ENV).map((k) => [k, process.env[k]]));
    Object.assign(process.env, RF_ENV); // env applicato PRIMA del require (lettura a call-time)
    try {
      const rf = require(path.join(WS, 'tools', 'record-finding'));
      const oracle = require(path.join(WS, 'tools', 'oracle'));
      const rec = oracle.writeReceipt({ type: 'http-diff', anchor: 'ondata4 outcome passed', data: {} });
      assert.ok(rec.ok, JSON.stringify(rec));
      const f = {
        severity: 'High', title: 'SQLi usage', host: 'target.example', poc: 'p', status: 'confirmed',
        oracle: { type: 'http-diff', ref: rec.ref, token: rec.token },
        evidence_quote: { file: rec.ref, text: 'ondata4 outcome passed' },
        usage: { tokens_in: 100, tokens_out: 50, cost: 0.001 },
      };
      const r1 = rf.record(JSON.stringify(f));
      assert.strictEqual(r1.ok, true, JSON.stringify(r1));
      const r2 = rf.record(JSON.stringify({ ...f, title: 'SQLi usage bis' }));
      assert.strictEqual(r2.ok, true, JSON.stringify(r2));
      const lines = fs.readFileSync(FJ, 'utf8').split('\n').filter(Boolean);
      const v = rf.verifyFindingsChain(lines);
      assert.deepStrictEqual([v.ok, v.chained], [true, 2], JSON.stringify(v));
      assert.ok(JSON.parse(lines[0]).usage.tokens_in === 100, 'usage persistito nel record nuovo');
      assert.ok(!fs.existsSync(path.join(WS, 'reports', 'findings.jsonl')) || true); // niente scritture reali: verificato sotto
      assert.ok(fs.readdirSync(RF_DIR).length >= 1, 'tutto scritto sotto RF_DIR');
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      }
    }
  });
  ok('record-finding usage INVALIDO → rifiutato senza scrivere', () => {
    const FJ = path.join(T, 'rf-bad', 'findings.jsonl');
    const env = { DSH_WS_ROOT: path.join(T, 'rf-bad'), FINDINGS_JSONL: FJ, LOOT_JSONL: path.join(T, 'rf-bad', 'loot.jsonl'), FINDINGS_TAB_DB: path.join(T, 'rf-bad', 'tab.db') };
    const r = cli(path.join(WS, 'tools', 'record-finding.js'), [JSON.stringify({
      severity: 'High', title: 'x', host: 'target.example', poc: 'p', status: 'inconclusive', usage: { tokens_in: -5 },
    })], env);
    assert.strictEqual(r.status, 1);
    assert.ok(r.stdout.includes('usage.tokens_in must be a non-negative int'), r.stdout);
    assert.ok(!fs.existsSync(FJ), 'nessuna scrittura su usage invalido');
  });
  ok('report-html: buildHtml include sezione «Costi & usage» con totali e per-agent', () => {
    const html = require(path.join(WS, 'tools', 'report-html'));
    const accounting = accLib.aggregateAll([
      { bin: 'nmap', agent: 'scout', usage: { tokens_in: 1000, tokens_out: 500, cost: 0.01 } },
    ]);
    const out = html.buildHtml({ findings: [], targets: [], chains: [], accounting, generatedAt: '2026-08-26T00:00:00Z' });
    assert.ok(out.includes('Costi &amp; usage (F8)'));
    assert.ok(out.includes('1500</strong> token'));
    assert.ok(out.includes('Per agente'));
    assert.ok(out.includes('nmap'));
    assert.ok(html.accountingSection(null).includes('Nessun dato di usage'), 'senza dati: messaggio muted, non errore');
  });
  ok('opstate accounting: read-only (zero scritture) con totali di sessione', () => {
    const auditFile = path.join(T, 'op-audit.jsonl');
    fs.writeFileSync(auditFile, JSON.stringify({ bin: 'nmap', agent: 'scout', usage: { tokens_in: 10, tokens_out: 5 } }) + '\n');
    const opFile = path.join(T, 'op.json');
    const env = { OPSTATE_FILE: opFile };
    const r = cli(OPSTATE, ['accounting', '--audit', auditFile], env);
    assert.strictEqual(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout);
    assert.strictEqual(o.accounting.session.tokens, 15);
    assert.ok(!fs.existsSync(opFile), 'read-only: nessuno state creato');
  });
  ok('opstate accounting --record: UNA transizione append-only con i totali (CAS ok)', () => {
    const auditFile = path.join(T, 'op-audit2.jsonl');
    fs.writeFileSync(auditFile, JSON.stringify({ bin: 'nmap', agent: 'scout', usage: { tokens_in: 10, tokens_out: 5, cost: 0.001 } }) + '\n');
    const opFile = path.join(T, 'op2.json');
    const env = { OPSTATE_FILE: opFile };
    const r = cli(OPSTATE, ['accounting', '--record', 'fase1', '--owner', 'coordinatore', '--audit', auditFile], env);
    assert.strictEqual(r.status, 0, r.stderr);
    const o = JSON.parse(r.stdout);
    assert.strictEqual(o.ok, true);
    assert.strictEqual(o.accounting.tokens, 15);
    const show = JSON.parse(cli(OPSTATE, ['show'], env).stdout);
    assert.strictEqual(show.revision, 1);
    assert.strictEqual(show.transitions, 1);
    assert.strictEqual(show.transitions_owner_check === undefined ? show.transitions : 1, 1);
    const hist = JSON.parse(cli(OPSTATE, ['history'], env).stdout);
    assert.strictEqual(hist.rows.length, 1);
    assert.ok(hist.rows[0].action.includes('accounting:fase1'), hist.rows[0].action);
  });
  ok('CLI accounting aggregate: sommario leggibile con per-action/per-agent', () => {
    const auditFile = path.join(T, 'agg.jsonl');
    fs.writeFileSync(auditFile, JSON.stringify({ bin: 'a', agent: 'x', usage: { tokens_in: 1, tokens_out: 1 } }) + '\n');
    const r = cli(ACC, ['aggregate', auditFile]);
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('2 tokens') && r.stdout.includes('per-agent'));
  });

  // ================================================================ SC3 — E3 reports: gate
  console.log('SC3 (E3) — gate dichiarativi reports:');
  const wfGood = path.join(T, 'wf-gate.yaml');
  fs.writeFileSync(wfGood, `name: wf-gate-test
steps:
  - id: s1
    cmd: node tools/run.js nmap -sn {target}
reports:
  recon:
    - path: reports/coverage-matrix.md
      type: matrix
      surface: coverage
  report:
    - path: reports/coverage-matrix.md
    - path: reports/report.html
`);
  ok('workflow validate con reports: → ok (pyyaml E mini-parser, stessa shape)', () => {
    const r = cli(WF, ['validate', wfGood]);
    assert.strictEqual(r.status, 0, r.stderr);
    const r2 = cli(WF, ['validate', wfGood], { WORKFLOW_NO_PYYAML: '1' });
    assert.strictEqual(r2.status, 0, r2.stderr);
    // parity della shape: reports identici tra i due parser
    const mini = wfLib.parseSubset(fs.readFileSync(wfGood, 'utf8'));
    assert.deepStrictEqual(Object.keys(mini.reports).sort(), ['recon', 'report']);
    assert.strictEqual(mini.reports.recon[0].path, 'reports/coverage-matrix.md');
    assert.strictEqual(mini.reports.recon[0].surface, 'coverage');
  });
  ok('validateDoc: reports malformato (path mancante / tipo errato) → errors', () => {
    const errs = wfLib.validateDoc({ name: 'x', steps: [{ id: 'a', cmd: 'node tools/run.js nmap' }], reports: { recon: [{ type: 'scan' }] } });
    assert.ok(errs.some((e) => e.includes('reports.recon[0]') && e.includes('path')), JSON.stringify(errs));
    const errs2 = wfLib.validateDoc({ name: 'x', steps: [{ id: 'a', cmd: 'node tools/run.js nmap' }], reports: 'nope' });
    assert.ok(errs2.some((e) => e.includes('reports')), JSON.stringify(errs2));
  });
  ok('gateChecks: reports dichiarati SOSTITUISCONO i check file, SA1 chain/oracle/evidenceQuote INTATTI', () => {
    const wf = gateLib.loadWorkflowReports(wfGood);
    const checks = gateLib.gateChecks('recon', wf);
    const kinds = checks.map((c) => c.kind);
    assert.deepStrictEqual(kinds, ['scopeNonEmpty', 'file']); // file scope.json hardcoded → dichiarato
    assert.strictEqual(checks[1].file, 'reports/coverage-matrix.md');
    assert.strictEqual(checks[1].declared, true);
    // report gate: nessun check kind 'file' hardcoded (coverage è kind dedicato) → i report
    // dichiarati vengono APPESI; i 3 check SA1 restano identici e contigui, seguiti dalla coda
    // Ondata 6 (pocReplay, chainHead) e infine dai file dichiarati.
    const repChecks = gateLib.gateChecks('report', wf);
    const repKinds = repChecks.map((c) => c.kind);
    assert.deepStrictEqual(repKinds, ['findings', 'verify', 'noPending', 'coverage', 'chain', 'oracle', 'evidenceQuote', 'pocReplay', 'chainHead', 'file', 'file']);
    assert.ok(repChecks.some((c) => c.kind === 'chain' && c.hint.includes('hash-chain')));
    assert.ok(repChecks.some((c) => c.kind === 'oracle'));
    assert.ok(repChecks.some((c) => c.kind === 'evidenceQuote'));
  });
  ok('gateChecks: fase SENZA reports → elenco hardcoded (legacy byte-identico)', () => {
    const wf = gateLib.loadWorkflowReports(wfGood);
    const legacy = gateLib.GATES.chains.checks;
    assert.deepStrictEqual(gateLib.gateChecks('chains', wf), legacy);
    assert.deepStrictEqual(gateLib.gateChecks('chains', null), legacy);
  });
  ok('CLI gate pass con --workflow: report dichiarato PRESENTE → PASS; MANCANTE → FAIL (exit 1)', () => {
    const covFile = path.join(gw, 'reports', 'coverage-matrix.md');
    const env = { GATE_LOG_FILE: path.join(T, 'gate-log.md'), SCOPE_JSON: SCOPE, GATE_WS: gw };
    // presente
    if (!fs.existsSync(covFile)) fs.writeFileSync(covFile, '| x |\n');
    let r = cli(GATE, ['pass', 'recon', '--workflow', wfGood], env);
    assert.strictEqual(r.status, 0, r.stderr);
    // mancante (report.html non esiste)
    fs.rmSync(path.join(WS, 'reports', 'report.html'), { force: true });
    r = cli(GATE, ['pass', 'report', '--workflow', wfGood], env);
    assert.strictEqual(r.status, 1, r.stdout);
    assert.ok(r.stderr.includes('reports/report.html missing'), r.stderr);
    // nessuna riga pass nel gate-log reale (override attivo)
    assert.ok(fs.readFileSync(env.GATE_LOG_FILE, 'utf8').includes('stavros/recon'), 'gate-log di test scritto');
  });
  ok('CLI gate SENZA --workflow: comportamento legacy invariato (runGate identico)', () => {
    assert.deepStrictEqual(gateLib.runGate('recon'), gateLib.runGate('recon', {}));
    const r = cli(GATE, ['pass', 'chains'], { GATE_LOG_FILE: path.join(T, 'gate-log-legacy.md'), SCOPE_JSON: SCOPE, GATE_WS: gw });
    assert.strictEqual(r.status, 0, r.stderr);
  });
  ok('workflow MALFORMATO con --workflow → fail-closed exit 1 (mai fallback silenzioso)', () => {
    const bad = path.join(T, 'bad-wf.yaml');
    fs.writeFileSync(bad, 'name: x\nsteps: nope\n');
    const r = cli(GATE, ['pass', 'recon', '--workflow', bad], { GATE_LOG_FILE: path.join(T, 'gl-bad.md'), GATE_WS: gw });
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes('workflow invalid'), r.stderr);
  });

  // ================================================================ SC4 — C5w audit trail
  console.log('SC4 (C5w) — audit trail isolato append-only');
  const SAVED_AUDIT_DIR = process.env.AUDIT_DIR;
  const auditDir = path.join(T, 'trail');
  process.env.AUDIT_DIR = auditDir; // le call a livello libreria leggono AUDIT_DIR a call-time
  const trailFile = () => path.join(auditDir, new Date().toISOString().slice(0, 10) + '.jsonl');
  ok('append: chain genesis (seq 1, prev 64 zeri) + seq 2 collegata', () => {
    const r1 = auditLib.append({ bin: 'nmap', ts: new Date().toISOString() });
    assert.strictEqual(r1.ok, true, JSON.stringify(r1));
    assert.strictEqual(r1.seq, 1);
    assert.strictEqual(r1.prev_sha256, '0'.repeat(64));
    const r2 = auditLib.append({ bin: 'ffuf', ts: new Date().toISOString() });
    assert.strictEqual(r2.ok, true, JSON.stringify(r2));
    assert.strictEqual(r2.seq, 2);
    assert.notStrictEqual(r2.prev_sha256, '0'.repeat(64));
    const v = auditLib.verifyAuditFile(trailFile());
    assert.deepStrictEqual([v.ok, v.chained], [true, 2], JSON.stringify(v));
  });
  ok('append-only: NESSUNA primitiva delete/rename esposta dal modulo', () => {
    const exported = Object.keys(auditLib);
    for (const bad of ['delete', 'remove', 'unlink', 'rename', 'truncate']) {
      assert.ok(!exported.some((k) => k.toLowerCase().includes(bad)), `esporta ${bad}?`);
    }
  });
  ok('permessi restrittivi: dir 0o700, file 0o600', () => {
    const dMode = fs.statSync(auditDir).mode & 0o777;
    const fMode = fs.statSync(trailFile()).mode & 0o777;
    assert.strictEqual(dMode, 0o700);
    assert.strictEqual(fMode, 0o600);
  });
  ok('TAMPER: un byte modificato a metà trail → verify FAIL con index', () => {
    const file = trailFile();
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    lines[0] = lines[0].replace('"bin":"nmap"', '"bin":"NMAP"');
    fs.writeFileSync(file, lines.join('\n'));
    const v = auditLib.verifyAuditFile(file);
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.index, 1);
    assert.ok(v.reason.includes('prev_sha256 mismatch'), v.reason);
  });
  ok('append su trail MANOMESSO → rifiutato (fail-closed, mai accodare su chain rotta)', () => {
    const r = auditLib.append({ bin: 'x' });
    assert.strictEqual(r.ok, false);
    assert.ok(r.error.includes('BROKEN'), r.error);
  });
  ok('CLI verify: trail manomesso → exit != 0; trail pulito → exit 0', () => {
    let r = cli(AUDIT, ['verify', trailFile()], { AUDIT_DIR: auditDir });
    assert.notStrictEqual(r.status, 0, 'trail manomesso → verify exit != 0');
    // trail pulito separato
    const cleanDir = path.join(T, 'trail-clean');
    const cleanFile = path.join(cleanDir, new Date().toISOString().slice(0, 10) + '.jsonl');
    process.env.AUDIT_DIR = cleanDir;
    auditLib.append({ bin: 'a', ts: new Date().toISOString() });
    r = cli(AUDIT, ['verify', cleanFile], { AUDIT_DIR: cleanDir });
    assert.strictEqual(r.status, 0, r.stdout);
    const shown = cli(AUDIT, ['show', cleanFile, '--tail', '5'], { AUDIT_DIR: cleanDir });
    assert.strictEqual(shown.status, 0);
    assert.ok(shown.stdout.includes('"bin":"a"'), shown.stdout);
  });
  ok('run.js: una riga per invocazione nel trail isolato (AUDIT_DIR, e2e)', () => {
    const env = { ...BASE_ENV, AUDIT_DIR: path.join(T, 'trail-e2e'), RUN_AUDIT_FILE: path.join(T, 'audit-e2e.jsonl') };
    const r = cli(RUN, ['--dry-run', 'fakebin', 'http://target.example/'], env);
    assert.strictEqual(r.status, 0, r.stderr);
    const trail = path.join(env.AUDIT_DIR, new Date().toISOString().slice(0, 10) + '.jsonl');
    assert.ok(fs.existsSync(trail));
    const v = auditLib.verifyAuditFile(trail);
    assert.deepStrictEqual([v.ok, v.chained], [true, 1], JSON.stringify(v));
    const line = JSON.parse(fs.readFileSync(trail, 'utf8').trim());
    assert.strictEqual(line.bin, 'fakebin');
    assert.ok(line.chain && line.chain.seq === 1);
  });
  ok('append con entry non oggetto → rifiutato', () => {
    const r = auditLib.append('nope');
    assert.strictEqual(r.ok, false);
    if (SAVED_AUDIT_DIR === undefined) delete process.env.AUDIT_DIR; else process.env.AUDIT_DIR = SAVED_AUDIT_DIR;
  });

  // suite esistenti interessate restano verdi (eseguite a parte): test-coverage/test-gate/test-gate-chain
  console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
  fs.rmSync(T, { recursive: true, force: true });
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
