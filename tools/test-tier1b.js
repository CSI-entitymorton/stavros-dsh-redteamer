#!/usr/bin/env node
// Tier 1-B test suite — tools/next-actions.js (finding-driven planner).
//   Funzionali: SMB/LDAP/HTTP/no-port -> azione attesa; SQLi/param/cred -> escalation attesa.
//   Coverage-aware: superficie gia enumerata NON riproposta (salvo --all).
//   Scope (fail-closed): host fuori scope -> blocked + escluso dall'eseguibile; scope non
//                        caricabile -> tutto bloccato.
//   Sicurezza: i segreti non compaiono MAI nell'output; intrusive = requires_optin.
//   Esecuzione: runPlan senza --yes rifiuta (no spawn). Integrazione reale via target-model.
//   Offline, fixture in mkdtemp.
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
const na = require(path.join(WS, 'tools', 'next-actions'));
const tm = require(path.join(WS, 'tools', 'target-model'));

const allow = () => ({ ok: true, reason: 'test-allow' });
const deny = () => ({ ok: false, reason: 'test-deny' });
const find = (p, surf) => p.actions.filter((a) => a.surface === surf);

// ---------------------------------------------------------------- pure planner
console.log('Tier 1-B — planner puro (funzionale)');

ok('no porte -> recon-baseline', () => {
  const snap = { targets: [{ host: '10.0.0.5', hosts: [{ address: '10.0.0.5', ports: [] }], endpoints: [], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  const a = find(p, 'network')[0];
  assert.ok(a && /recon-baseline/.test(a.cmd));
});

ok('SMB aperto -> enum-smb', () => {
  const snap = { targets: [{ host: '192.168.0.94', hosts: [{ address: '192.168.0.94', ports: [{ port: 445, protocol: 'tcp', service: 'microsoft-ds', state: 'open' }] }], endpoints: [], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  assert.ok(find(p, 'smb').length === 1, 'una azione smb');
  assert.ok(/enum-smb/.test(find(p, 'smb')[0].cmd));
});

ok('LDAP aperto -> enum-ldap (tier read)', () => {
  const snap = { targets: [{ host: 'dc.lab', hosts: [{ address: '10.0.0.6', ports: [{ port: 389, service: 'ldap', state: 'open' }] }], endpoints: [], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  const a = find(p, 'ldap')[0];
  assert.strictEqual(a.tier, 'read');
});

ok('HTTP aperto senza endpoint -> enum-http', () => {
  const snap = { targets: [{ host: 'web.lab', hosts: [{ address: '10.0.0.7', ports: [{ port: 80, service: 'http', state: 'open' }] }], endpoints: [], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  assert.ok(find(p, 'http').some((a) => /enum-http/.test(a.cmd)));
});

ok('coverage-aware: HTTP gia enumerato NON riproposto (salvo --all)', () => {
  const snap = { targets: [{ host: 'web.lab', hosts: [{ address: '10.0.0.7', ports: [{ port: 80, service: 'http', state: 'open' }] }], endpoints: [{ method: 'GET', url: 'http://web.lab/' }], vulns: [], creds: [] }] };
  const noAll = na.plan(snap, { inScope: allow });
  assert.ok(!find(noAll, 'http').some((a) => /enum-http/.test(a.cmd)), 'enum-http non riproposto');
  const withAll = na.plan(snap, { inScope: allow, all: true });
  assert.ok(find(withAll, 'http').some((a) => /enum-http/.test(a.cmd)), 'con --all torna');
});

ok('endpoint noti + 0 vuln -> nuclei mirato', () => {
  const snap = { targets: [{ host: 'web.lab', hosts: [{ address: '10.0.0.7', ports: [{ port: 80, service: 'http', state: 'open' }] }], endpoints: [{ method: 'GET', url: 'http://web.lab/' }], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  assert.ok(find(p, 'http').some((a) => a.ref === 'nuclei'));
});

// ---------------------------------------------------------------- finding-driven escalation
console.log('Tier 1-B — escalation finding-driven');

ok('endpoint con parametri -> sqlmap (intrusive, opt-in)', () => {
  const snap = { targets: [{ host: 'web.lab', hosts: [{ address: '10.0.0.7', ports: [{ port: 80, service: 'http', state: 'open' }] }], endpoints: [{ method: 'GET', url: 'http://web.lab/item?id=1' }], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  const a = find(p, 'http-param')[0];
  assert.ok(a, 'azione http-param presente');
  assert.strictEqual(a.tier, 'intrusive');
  assert.strictEqual(a.requires_optin, true);
});

ok('SQLi rilevata -> sqlmap --dbs', () => {
  const snap = { targets: [{ host: 'web.lab', hosts: [{ address: '10.0.0.7', ports: [{ port: 80, service: 'http', state: 'open' }] }], endpoints: [], vulns: [{ class: 'sqli', url: 'http://web.lab/item?id=1', template_id: 'sqli-error' }], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  const a = find(p, 'sqli')[0];
  assert.ok(a && /--dbs/.test(a.cmd) && a.requires_optin === true);
});

ok('credenziale -> enum autenticata, SEGRETO MAI in chiaro', () => {
  const snap = { targets: [{ host: '192.168.0.94', hosts: [{ address: '192.168.0.94', ports: [{ port: 445, service: 'microsoft-ds', state: 'open' }] }], endpoints: [], vulns: [], creds: [{ host: '192.168.0.94', username: 'administrator', kind: 'password' }] }] };
  const p = na.plan(snap, { inScope: allow });
  const a = find(p, 'creds')[0];
  assert.ok(a && a.requires_optin === true);
  assert.ok(a.cmd.includes('<secret>'), 'placeholder segreto');
  assert.ok(!JSON.stringify(p).includes('P@ssw0rd'));
});

// ---------------------------------------------------------------- scope (fail-closed)
console.log('Tier 1-B — scope fail-closed');

ok('host fuori scope -> blocked + non eseguibile', () => {
  const snap = { targets: [{ host: '8.8.8.8', hosts: [{ address: '8.8.8.8', ports: [{ port: 445, service: 'microsoft-ds', state: 'open' }] }], endpoints: [], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: deny });
  assert.ok(p.actions.every((a) => a.blocked === true));
  assert.strictEqual(p.summary.executable, 0);
});

ok('summary.executable esclude covered/intrusive/blocked', () => {
  const snap = { targets: [{ host: 'web.lab', hosts: [{ address: '10.0.0.7', ports: [{ port: 80, service: 'http', state: 'open' }, { port: 445, service: 'microsoft-ds', state: 'open' }] }], endpoints: [{ method: 'GET', url: 'http://web.lab/item?id=1' }], vulns: [], creds: [] }] };
  const p = na.plan(snap, { inScope: allow });
  // eseguibili attesi: enum-smb (active) + nuclei mirato (active); NON http-param (intrusive), NON enum-http (covered)
  const execNames = p.actions.filter((a) => !a.blocked && !a.covered && !a.requires_optin).map((a) => a.ref);
  assert.strictEqual(p.summary.executable, execNames.length);
  assert.ok(execNames.includes('nuclei'));
  assert.ok(!p.actions.filter((a) => a.surface === 'http-param')[0] || p.actions.filter((a) => a.surface === 'http-param')[0].requires_optin);
});

// ---------------------------------------------------------------- integrazione reale + esecuzione
console.log('Tier 1-B — integrazione target-model + esecuzione fail-closed');
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'tier1b-'));
process.env.STATE_DB = path.join(T, 'state.db');
process.env.SCOPE_JSON = path.join(T, 'scope.json');
fs.writeFileSync(process.env.SCOPE_JSON, JSON.stringify({ targets: ['192.168.0.0/24'], exclusions: [] }));

ok('planFromDb: modello popolato -> azioni con verdetto scope reale', () => {
  const db = tm.open();
  const NMAP = '<nmaprun><host><address addr="192.168.0.94" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports></host></nmaprun>';
  tm.ingest(db, 'nmap', NMAP, {});
  const p = na.planFromDb(db, {});
  db.close();
  const smb = p.actions.find((a) => a.surface === 'smb');
  assert.ok(smb, 'azione smb presente');
  assert.strictEqual(smb.blocked, false, 'in-scope: non bloccato');
  assert.ok(/allowlisted/.test(smb.scope_reason));
});

ok('planFromDb: host fuori scope reale -> blocked', () => {
  const db = tm.open();
  const NMAP = '<nmaprun><host><address addr="8.8.8.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>';
  tm.ingest(db, 'nmap', NMAP, {});
  const p = na.planFromDb(db, {});
  db.close();
  const g = p.actions.find((a) => a.host === '8.8.8.8');
  assert.ok(g && g.blocked === true);
});

ok('runPlan senza --yes -> rifiutato (nessuno spawn)', () => {
  const db = tm.open();
  const res = na.runPlan(db, {});
  db.close();
  assert.strictEqual(res.ok, false);
  assert.ok(/--yes/.test(res.reason));
});

ok('CLI plan -> exit 0 JSON', () => {
  const p = spawnSync('node', [path.join(WS, 'tools', 'next-actions.js'), 'plan'], { env: process.env, encoding: 'utf8' });
  assert.strictEqual(p.status, 0, p.stderr);
  const out = JSON.parse(p.stdout);
  assert.ok(Array.isArray(out.actions));
});

ok('CLI run senza --yes -> exit 2', () => {
  const p = spawnSync('node', [path.join(WS, 'tools', 'next-actions.js'), 'run'], { env: process.env, encoding: 'utf8' });
  assert.strictEqual(p.status, 2);
});

console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
try { fs.rmSync(T, { recursive: true, force: true }); } catch {}
process.exit(fail === 0 ? 0 : 1);
