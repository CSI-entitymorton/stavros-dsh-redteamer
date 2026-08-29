#!/usr/bin/env node
// Tier 1-C test suite — tools/coverage-loop.js (coverage-driven completeness).
//   relevantClasses: superfici -> classi rilevanti attese (http->sqli/xss; smb->network...).
//   computeGaps: classe con Vuln nel modello = coperta; le altre rilevanti = gap; pct coerente.
//   Loop: remaining()/isDry() convergenza corretta.
//   Integrazione reale: ingest nel target-model -> gap che si RIDUCONO dopo nuova evidenza.
//   Offline, coverage sources (reportsDir/findingsFile) in mkdtemp: MAI reports/ reale.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { spawnSync } = require('child_process');

let pass = 0; let fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}: ${e.message}`); }
}

const WS = path.join(__dirname, '..');
const cl = require(path.join(WS, 'tools', 'coverage-loop'));
const tm = require(path.join(WS, 'tools', 'target-model'));

const T = fs.mkdtempSync(path.join(os.tmpdir(), 'tier1c-'));
const EMPTY_REPORTS = fs.mkdtempSync(path.join(T, 'rep-'));
const OPTS = { reportsDir: EMPTY_REPORTS, findingsFile: path.join(EMPTY_REPORTS, 'findings.jsonl') };

const httpTarget = (vulns) => ({ host: 'web.lab', hosts: [{ address: '10.0.0.7', ports: [{ port: 80, service: 'http', state: 'open' }] }], endpoints: [{ method: 'GET', url: 'http://web.lab/' }], vulns: vulns || [], creds: [] });
const smbTarget = { host: '192.168.0.94', hosts: [{ address: '192.168.0.94', ports: [{ port: 445, service: 'microsoft-ds', state: 'open' }] }], endpoints: [], vulns: [], creds: [] };

// ---------------------------------------------------------------- relevantClasses
console.log('Tier 1-C — classi rilevanti per superficie');
ok('HTTP -> include sqli/xss/idor', () => {
  const r = cl.relevantClasses(httpTarget());
  for (const c of ['sqli', 'xss', 'idor', 'authn']) assert.ok(r.includes(c), `manca ${c}`);
});
ok('SMB -> include network/authn, NON sqli', () => {
  const r = cl.relevantClasses(smbTarget);
  assert.ok(r.includes('network') && r.includes('authn'));
  assert.ok(!r.includes('sqli'));
});
ok('base sempre presente (network/config)', () => {
  const r = cl.relevantClasses({ host: 'x', hosts: [{ address: 'x', ports: [{ port: 22, service: 'ssh', state: 'open' }] }], endpoints: [], vulns: [] });
  assert.ok(r.includes('network') && r.includes('config') && r.includes('crypto'));
});

// ---------------------------------------------------------------- computeGaps
console.log('Tier 1-C — computeGaps');
ok('nessuna vuln -> tutte le classi rilevanti sono gap', () => {
  const g = cl.computeGaps(httpTarget(), OPTS);
  assert.strictEqual(g.covered.length, 0);
  assert.strictEqual(g.gaps.length, g.relevant.length);
  assert.strictEqual(g.coverage_pct, 0);
});
ok('vuln sqli -> sqli coperto, resta gap sulle altre', () => {
  const g = cl.computeGaps(httpTarget([{ class: 'sqli', url: 'http://web.lab/item?id=1', template_id: 'sqli-x' }]), OPTS);
  assert.ok(g.covered.includes('sqli'), 'sqli coperto');
  assert.ok(!g.gaps.includes('sqli'), 'sqli non e piu gap');
  assert.ok(g.gaps.includes('xss'), 'xss ancora gap');
  assert.ok(g.coverage_pct > 0 && g.coverage_pct < 100);
});
ok('nextForGaps: ogni gap ha un probe', () => {
  const g = cl.computeGaps(httpTarget(), OPTS);
  const probes = cl.nextForGaps(g);
  assert.strictEqual(probes.length, g.gaps.length);
  assert.ok(probes.every((p) => typeof p.probe === 'string' && p.probe.length));
});

// ---------------------------------------------------------------- loop convergence
console.log('Tier 1-C — convergenza loop');
ok('remaining somma i gap; isDry rileva stallo', () => {
  const reps = [cl.computeGaps(httpTarget(), OPTS), cl.computeGaps(smbTarget, OPTS)];
  const rem = cl.remaining(reps);
  assert.ok(rem > 0);
  assert.strictEqual(cl.isDry(5, 5), true);   // nessuna riduzione -> dry
  assert.strictEqual(cl.isDry(5, 3), false);  // progresso -> non dry
});

// ---------------------------------------------------------------- integrazione reale (gap si riduce)
console.log('Tier 1-C — integrazione: nuova evidenza riduce i gap');
process.env.STATE_DB = path.join(T, 'state.db');
ok('ingest nuclei sqli -> coverage_pct aumenta', () => {
  const db = tm.open();
  const NMAP = '<nmaprun><host><address addr="10.0.0.7" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>';
  tm.ingest(db, 'nmap', NMAP, {});
  const before = cl.gapsFromDb(db, OPTS)[0];
  const NUCLEI = '{"template-id":"sqli-error","matched-at":"http://10.0.0.7/item?id=1","info":{"name":"SQL Injection","severity":"high","tags":["sqli"]}}';
  tm.ingest(db, 'nuclei', NUCLEI, {});
  const after = cl.gapsFromDb(db, OPTS)[0];
  db.close();
  assert.ok(after.coverage_pct > before.coverage_pct, `pct: ${before.coverage_pct} -> ${after.coverage_pct}`);
  assert.ok(before.gaps.includes('sqli') && !after.gaps.includes('sqli'));
});

// ---------------------------------------------------------------- CLI exit code (gate)
console.log('Tier 1-C — CLI come gate di completezza');
ok('CLI gaps con gap residui -> exit 1', () => {
  const env = { ...process.env, STATE_DB: path.join(T, 'state.db'), COVERAGE_REPORTS_DIR: EMPTY_REPORTS, FINDINGS_JSONL: OPTS.findingsFile };
  const p = spawnSync('node', [path.join(WS, 'tools', 'coverage-loop.js'), 'gaps'], { env, encoding: 'utf8' });
  assert.strictEqual(p.status, 1, 'gap residui => exit 1');
  const reps = JSON.parse(p.stdout);
  assert.ok(Array.isArray(reps) && reps.length >= 1);
});

console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
try { fs.rmSync(T, { recursive: true, force: true }); } catch {}
process.exit(fail === 0 ? 0 : 1);
