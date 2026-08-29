#!/usr/bin/env node
// Tier 1-A test suite — tools/target-model.js (normalized asset graph).
//   Funzionali: ingest nmap/httpx/ffuf/nuclei/netexec -> modello popolato; snapshot coerente;
//               entità tipizzate valide vs docs/entity-taxonomy.yaml; integrazione coverage.
//   Idempotenza: ri-ingest della stessa evidenza -> nessuna riga duplicata.
//   Avversariali: tool sconosciuto -> ok:false (no throw); input malformato -> zero righe (no throw);
//                 nessuna entità spuria (invalid == []).
//   Tutto offline, fixture in mkdtemp, STATE_DB su file temporaneo (MAI il db reale).
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
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'tier1a-'));
process.env.STATE_DB = path.join(T, 'state.db');

const tm = require(path.join(WS, 'tools', 'target-model'));
const et = require(path.join(WS, 'tools', 'entity-taxonomy'));

// ---------------------------------------------------------------- fixtures
const NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
<host>
  <address addr="192.168.0.94" addrtype="ipv4"/>
  <hostname name="dc01.lab.local"/>
  <os><osmatch name="Linux 5.x"/></os>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
    <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
  </ports>
</host>
</nmaprun>`;

const HTTPX = [
  '{"url":"http://192.168.0.94/","status_code":200,"title":"Home","webserver":"nginx","tech":["Nginx","PHP"],"host":"192.168.0.94","input":"192.168.0.94"}',
  'garbage-not-json',
  '{"url":"http://192.168.0.94/login","status_code":401,"webserver":"nginx","host":"192.168.0.94"}',
].join('\n');

const FFUF = [
  '{"url":"http://192.168.0.94/admin","status":200,"length":123,"words":10,"lines":5}',
  '{"url":"http://192.168.0.94/backup","status":301,"length":0,"words":1,"lines":1}',
].join('\n');

const NUCLEI = [
  '{"template-id":"sqli-error-based","matched-at":"http://192.168.0.94/item?id=1","info":{"name":"SQL Injection Error Based","severity":"high","tags":["sqli","injection"],"classification":{"cve-id":["CVE-2021-1234"]}}}',
  '{"template-id":"tls-version","matched-at":"192.168.0.94:443","info":{"name":"TLS 1.0 enabled","severity":"low","tags":["ssl","crypto"]}}',
].join('\n');

const NETEXEC = [
  'SMB   192.168.0.94   445   DC01   [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:lab.local) (signing:True) (SMBv1:False)',
  'SMB   192.168.0.94   445   DC01   [+] lab.local\\administrator:P@ssw0rd (Pwn3d!)',
  'SMB   192.168.0.94   445   DC01   Share           Permissions     Remark',
  'SMB   192.168.0.94   445   DC01   -----           -----------     ------',
  'SMB   192.168.0.94   445   DC01   ADMIN$                          Remote Admin',
  'SMB   192.168.0.94   445   DC01   C$                              Default share',
].join('\n');

// ---------------------------------------------------------------- functional
console.log('Tier 1-A — ingest funzionale');
const db = tm.open();

ok('ingest nmap -> 1 host, 2 porte', () => {
  const r = tm.ingest(db, 'nmap', NMAP_XML, {});
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.counts.hosts, 1);
  assert.strictEqual(r.counts.ports, 2);
});

ok('nmap: os + servizi persistiti', () => {
  const snap = tm.snapshot(db);
  const t = snap.targets.find((x) => x.host === '192.168.0.94');
  assert.ok(t, 'target presente');
  const h = t.hosts[0];
  assert.strictEqual(h.os, 'Linux 5.x');
  const ssh = h.ports.find((p) => p.port === 22);
  assert.strictEqual(ssh.service, 'ssh');
  assert.strictEqual(ssh.version, '8.9');
  assert.ok(h.ports.find((p) => p.port === 445 && p.service === 'microsoft-ds'));
});

ok('idempotenza: ri-ingest nmap NON duplica', () => {
  tm.ingest(db, 'nmap', NMAP_XML, {});
  const snap = tm.snapshot(db);
  const t = snap.targets.find((x) => x.host === '192.168.0.94');
  assert.strictEqual(t.hosts.length, 1);
  assert.strictEqual(t.hosts[0].ports.length, 2);
});

ok('ingest httpx -> endpoints (riga malformata saltata)', () => {
  const r = tm.ingest(db, 'httpx', HTTPX, {});
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.counts.endpoints, 2); // la riga garbage non conta
  const snap = tm.snapshot(db);
  const t = snap.targets.find((x) => x.host === '192.168.0.94');
  assert.ok(t.endpoints.find((e) => e.url === 'http://192.168.0.94/'));
  assert.ok(t.endpoints.find((e) => e.url === 'http://192.168.0.94/login'));
});

ok('ingest ffuf -> endpoints', () => {
  const r = tm.ingest(db, 'ffuf', FFUF, {});
  assert.strictEqual(r.counts.endpoints, 2);
  const t = tm.snapshot(db).targets.find((x) => x.host === '192.168.0.94');
  assert.ok(t.endpoints.find((e) => e.url === 'http://192.168.0.94/admin'));
});

ok('ingest nuclei -> vuln classificata sqli', () => {
  const r = tm.ingest(db, 'nuclei', NUCLEI, {});
  assert.strictEqual(r.counts.vulns, 2);
  const vulns = tm.listVulns(db);
  const sqli = vulns.find((v) => v.template_id === 'sqli-error-based');
  assert.strictEqual(sqli.class, 'sqli');
  assert.strictEqual(sqli.severity, 'high');
  assert.ok(String(sqli.cve).includes('CVE-2021-1234'));
});

ok('ingest netexec -> host + cred + share', () => {
  const r = tm.ingest(db, 'netexec', NETEXEC, {});
  assert.strictEqual(r.ok, true);
  assert.ok(r.counts.creds >= 1, 'almeno una cred');
  const creds = tm.listCreds(db, '192.168.0.94');
  const admin = creds.find((c) => c.username.includes('administrator'));
  assert.ok(admin, 'cred administrator presente');
  assert.strictEqual(admin.secret, 'P@ssw0rd');
  assert.strictEqual(admin.validated, 1);
  const t = tm.snapshot(db).targets.find((x) => x.host === '192.168.0.94');
  assert.ok(t.endpoints.find((e) => e.method === 'SMB' && e.url.endsWith('/ADMIN$')));
});

// ---------------------------------------------------------------- typed entities
console.log('Tier 1-A — entità tipizzate');
ok('toEntities: nessuna entità spuria (invalid vuoto)', () => {
  const { entities, invalid } = tm.toEntities(db);
  assert.deepStrictEqual(invalid, [], 'nessuna entità invalida: ' + JSON.stringify(invalid));
  assert.ok(entities.length > 0);
});

ok('toEntities: tipi attesi presenti', () => {
  const { entities } = tm.toEntities(db);
  const types = new Set(entities.map((e) => e.entityType));
  for (const want of ['Target', 'Port', 'Service', 'Vuln']) assert.ok(types.has(want), `manca ${want}`);
});

ok('toEntities: rivalidazione batch vs taxonomy = ok', () => {
  const { entities } = tm.toEntities(db);
  const res = et.validateEntities(entities);
  assert.strictEqual(res.ok, true, JSON.stringify(res.errors));
});

ok('integrazione coverage: sqli tra le classi coperte', () => {
  const { entities } = tm.toEntities(db);
  const covered = et.coveredClassesFromEntities(entities);
  assert.ok(covered.includes('sqli'), 'covered=' + covered.join(','));
});

// ---------------------------------------------------------------- adversarial / fail-closed
console.log('Tier 1-A — avversariali / fail-closed');
ok('tool sconosciuto -> ok:false, nessun throw', () => {
  const r = tm.ingest(db, 'metasploit', 'whatever', {});
  assert.strictEqual(r.ok, false);
  assert.ok(/unknown tool/.test(r.reason));
});

ok('input malformato -> zero righe, nessun throw', () => {
  const before = tm.listVulns(db).length;
  const r = tm.ingest(db, 'nuclei', '\n\nnot-json\n{bad', {});
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.counts.vulns, 0);
  assert.strictEqual(tm.listVulns(db).length, before);
});

ok('nmap XML vuoto -> zero host, nessun throw', () => {
  const r = tm.ingest(db, 'nmap', '<nmaprun></nmaprun>', {});
  assert.strictEqual(r.counts.hosts, 0);
});

db.close();

// ---------------------------------------------------------------- CLI end-to-end (spawn reale)
console.log('Tier 1-A — CLI end-to-end');
const T2 = fs.mkdtempSync(path.join(os.tmpdir(), 'tier1a-cli-'));
const env = { ...process.env, STATE_DB: path.join(T2, 'state.db') };
const nmapFile = path.join(T2, 'scan.xml');
fs.writeFileSync(nmapFile, NMAP_XML);

ok('CLI ingest nmap -> exit 0, ok:true', () => {
  const p = spawnSync('node', [path.join(WS, 'tools', 'target-model.js'), 'ingest', 'nmap', nmapFile], { env, encoding: 'utf8' });
  assert.strictEqual(p.status, 0, p.stderr);
  assert.strictEqual(JSON.parse(p.stdout).ok, true);
});

ok('CLI ingest tool sconosciuto -> exit 1', () => {
  const f = path.join(T2, 'x.txt'); fs.writeFileSync(f, 'x');
  const p = spawnSync('node', [path.join(WS, 'tools', 'target-model.js'), 'ingest', 'foobar', f], { env, encoding: 'utf8' });
  assert.strictEqual(p.status, 1);
});

ok('CLI snapshot -> JSON con il target', () => {
  const p = spawnSync('node', [path.join(WS, 'tools', 'target-model.js'), 'snapshot'], { env, encoding: 'utf8' });
  assert.strictEqual(p.status, 0, p.stderr);
  const snap = JSON.parse(p.stdout);
  assert.ok(snap.targets.some((t) => t.host === '192.168.0.94'));
});

ok('CLI creds -> secret mascherato', () => {
  // ingest netexec via CLI, poi verifica che il segreto non trapeli in chiaro.
  const nf = path.join(T2, 'nxc.txt'); fs.writeFileSync(nf, NETEXEC);
  spawnSync('node', [path.join(WS, 'tools', 'target-model.js'), 'ingest', 'netexec', nf], { env, encoding: 'utf8' });
  const p = spawnSync('node', [path.join(WS, 'tools', 'target-model.js'), 'creds'], { env, encoding: 'utf8' });
  assert.strictEqual(p.status, 0, p.stderr);
  assert.ok(!p.stdout.includes('P@ssw0rd'), 'il segreto non deve comparire in chiaro');
  assert.ok(p.stdout.includes('***'));
});

// ---------------------------------------------------------------- summary
console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
try { fs.rmSync(T, { recursive: true, force: true }); fs.rmSync(T2, { recursive: true, force: true }); } catch {}
process.exit(fail === 0 ? 0 : 1);
