#!/usr/bin/env node
// Ondata 3 — SC1 test suite (B9 SSRF default-deny anti-metadata + mitigazione-S di A4):
//   B9  : tools/ssrf-guard.js come SECONDO layer dentro repeater.js/oob.js (scope-guard resta
//         il primo layer). Funzionali: tier matrix, opt-in esplicito, lab privato in-scope
//         operativo. Avversariali: scope che CONSENTI esplicitamente metadata/loopback ->
//         il secondo layer nega comunque; state OOB manomesso verso metadata -> rifiutato.
//   A4-S: tools/listen-audit.js read-only (ss/netstat/proc) con fixture deterministica +
//         rilevazione REALE di un listener locale + append evidence-index single-writer.
// Offline tranne lo smoke sul lab autorizzato 192.168.0.94 (come da prassi ondate precedenti).
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
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

const WS = '/home/stavros/Desktop/Redteamingtest';
const sg = require(path.join(WS, 'tools', 'ssrf-guard'));
const la = require(path.join(WS, 'tools', 'listen-audit'));

function writeScope(dir, obj) {
  const f = path.join(dir, 'scope.json');
  fs.writeFileSync(f, JSON.stringify(obj));
  return f;
}

async function main() {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'sc1-'));

  // ---------------------------------------------------------------- B9 unit matrix
  console.log('B9 — ssrf-guard unit matrix');
  ok('hard tier: 169.254.169.254 negato anche con scopeAuthorized', () => {
    const v = sg.checkAddress('169.254.169.254', { scopeAuthorized: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.tier, 'hard');
  });
  ok('hard tier: loopback v4/v6/mapped negati', () => {
    for (const ip of ['127.0.0.1', '127.8.8.8', '::1', '::ffff:127.0.0.1']) {
      const v = sg.checkAddress(ip, { scopeAuthorized: true });
      assert.strictEqual(v.ok, false, ip);
      assert.strictEqual(v.tier, 'hard', ip);
    }
  });
  ok('hard tier: link-local v6 fe80::/10 e unspecified/multicast/reserved', () => {
    for (const ip of ['fe80::1', '0.0.0.0', '::', '224.0.0.1', '240.0.0.1']) {
      assert.strictEqual(sg.checkAddress(ip, {}).ok, false, ip);
    }
  });
  ok('hostname metadata noti negati (metadata.google.internal, localhost)', () => {
    for (const h of ['metadata.google.internal', 'localhost', 'instance-data']) {
      const v = sg.checkTarget('http://' + h + '/', {});
      assert.strictEqual(v.ok, false, h);
      assert.strictEqual(v.tier, 'hard', h);
    }
  });
  ok('private tier: RFC1918 negato SENZA autorizzazione scope, consentito CON scopeAuthorized', () => {
    assert.strictEqual(sg.checkAddress('10.1.2.3', {}).ok, false);
    assert.strictEqual(sg.checkAddress('172.16.5.5', {}).ok, false);
    assert.strictEqual(sg.checkAddress('192.168.1.10', {}).ok, false);
    const v = sg.checkAddress('192.168.0.94', { scopeAuthorized: true });
    assert.strictEqual(v.ok, true);
    assert.strictEqual(v.tier, 'pass-private-scoped');
  });
  ok('opt-in --allow-metadata-target solleva ENTRAMBI i tier in modo visibile', () => {
    const a = sg.checkAddress('169.254.169.254', { allowMetadata: true });
    const b = sg.checkAddress('192.168.7.7', { allowMetadata: true });
    assert.strictEqual(a.ok, true); assert.strictEqual(a.tier, 'pass-optin');
    assert.strictEqual(b.ok, true); assert.strictEqual(b.tier, 'pass-optin');
  });
  ok('indirizzi pubblici neutrali passano senza rumore', () => {
    assert.deepStrictEqual(sg.checkAddress('8.8.8.8', {}), { ok: true, tier: 'pass', range: null });
    assert.deepStrictEqual(sg.checkAddress('203.0.113.10', { scopeAuthorized: true }), { ok: true, tier: 'pass', range: null });
  });

  // ------------------------------------------------- B9 adversarial e2e via repeater CLI
  // Scope ostile: CONSENTE esplicitamente metadata e loopback (caso peggiore per il layer 1).
  const hostileScope = writeScope(T, {
    allowed_hosts: ['169.254.169.254', '127.0.0.1'],
    allowed_ips: ['169.254.169.254/32', '127.0.0.0/8'],
    max_requests_per_second: 100,
  });
  const envBase = { ...process.env, SCOPE_JSON: hostileScope };
  console.log('B9 — repeater e2e avversariale (layer-1 lascia passare, il layer-2 deve bloccare)');
  ok('metadata IP in-scope SENZA flag -> exit≠0, gate ssrf-guard, nessun output risposta', () => {
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'repeater.js'), '--url', 'http://169.254.169.254/latest/meta-data/', '--timeout', '1500'], { encoding: 'utf8', env: envBase, timeout: 20000 });
    assert.notStrictEqual(r.status, 0, 'deve fallire');
    assert.ok(r.stderr.includes('"gate":"ssrf-guard"'), 'manca gate ssrf-guard: ' + r.stderr.slice(0, 300));
    assert.ok(r.stderr.includes('link-local'), r.stderr.slice(0, 200));
    assert.ok(!r.stdout.includes('"status"'), 'nessuna richiesta deve partire');
  });
  ok('loopback in-scope SENZA flag -> exit≠0 tier hard', () => {
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'repeater.js'), '--url', 'http://127.0.0.1:9099/', '--timeout', '1500'], { encoding: 'utf8', env: envBase, timeout: 20000 });
    assert.notStrictEqual(r.status, 0);
    assert.ok(r.stderr.includes('"tier":"hard"') && r.stderr.includes('loopback'), r.stderr.slice(0, 300));
  });
  ok('opt-in flag -> verdetto pass-optin loggato, la richiesta PARTE (poi errore rete, non block)', async () => {
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'repeater.js'), '--url', 'http://169.254.169.254/', '--timeout', '1200', '--allow-metadata-target'], { encoding: 'utf8', env: envBase, timeout: 25000 });
    assert.ok(r.stderr.includes('pass-optin'), r.stderr.slice(0, 300));
    assert.ok(!r.stderr.includes('"gate":"ssrf-guard"'), 'il layer non deve più bloccare');
  });
  ok('env ALLOW_METADATA_TARGET=1 equivalente al flag (loud)', () => {
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'repeater.js'), '--url', 'http://169.254.169.254/', '--timeout', '1200'], { encoding: 'utf8', env: { ...envBase, ALLOW_METADATA_TARGET: '1' }, timeout: 25000 });
    assert.ok(r.stderr.includes('ALLOW_METADATA_TARGET attivo'), r.stderr.slice(0, 300));
  });
  ok('lab privato 192.168.0.94 IN scope -> pass-private-scoped + HTTP 200 reale (nessuna rottura)', async () => {
    const labScope = writeScope(T, { targets: ['192.168.0.94'], exclusions: [], max_requests_per_second: 50 });
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'repeater.js'), '--url', 'http://192.168.0.94/', '--timeout', '6000'], { encoding: 'utf8', env: { ...process.env, SCOPE_JSON: labScope }, timeout: 40000 });
    assert.strictEqual(r.status, 0, 'stderr: ' + r.stderr.slice(0, 400));
    assert.ok(r.stderr.includes('pass-private-scoped'), r.stderr.slice(0, 200));
    assert.ok(r.stdout.includes('"status": 200'), r.stdout.slice(0, 300));
  }, );

  // ---------------------------------------------------------------- B9 oob.js guard
  console.log('B9 — oob.js public-url/marker guard');
  ok('listen --public-url metadata -> rifiutato exit≠0', () => {
    const oobDir = path.join(T, 'oob-a'); fs.mkdirSync(oobDir, { recursive: true });
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'oob.js'), 'listen', '--port', '19099', '--public-url', 'http://169.254.169.254/x/'], { encoding: 'utf8', env: { ...process.env, OOB_DIR: oobDir, OOB_STATE_FILE: path.join(oobDir, 'state.json') }, timeout: 15000 });
    assert.notStrictEqual(r.status, 0);
    assert.ok(r.stderr.includes('"gate":"ssrf-guard"'), r.stderr.slice(0, 300));
    assert.ok(!fs.existsSync(path.join(oobDir, 'state.json')), 'nessuno state deve essere scritto');
  });
  ok('state OOB manomesso verso metadata -> marker RIFIUTATO (difesa su base letta dallo state)', () => {
    const oobDir = path.join(T, 'oob-b'); fs.mkdirSync(oobDir, { recursive: true });
    const stateFile = path.join(oobDir, 'state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ pid: 1, port: 9099, public_url: 'http://169.254.169.254/tampered/', started: 'now' }));
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'oob.js'), 'marker'], { encoding: 'utf8', env: { ...process.env, OOB_DIR: oobDir, OOB_STATE_FILE: stateFile }, timeout: 15000 });
    assert.notStrictEqual(r.status, 0);
    assert.ok(r.stderr.includes('link-local'), r.stderr.slice(0, 300));
    assert.strictEqual(fs.readdirSync(oobDir).filter((f) => f !== 'state.json').length, 0, 'nessun marker registrato');
  });
  ok('public-url normale (host di lab) -> marker emesso normalmente', () => {
    const oobDir = path.join(T, 'oob-c'); fs.mkdirSync(oobDir, { recursive: true });
    const stateFile = path.join(oobDir, 'state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ pid: 1, port: 9099, public_url: 'http://192.168.0.94:9099/', started: 'now' }));
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'oob.js'), 'marker'], { encoding: 'utf8', env: { ...process.env, OOB_DIR: oobDir, OOB_STATE_FILE: stateFile }, timeout: 15000 });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(/http:\/\/192\.168\.0\.94:9099\/[0-9a-f]{16}/.test(r.stdout.trim()), r.stdout);
  });

  // ---------------------------------------------------------------- A4-S listen-audit
  console.log('A4-S — listen-audit read-only');
  const auditScope = writeScope(T, { targets: ['192.168.0.94'], exclusions: [] });
  const ssFixture = [
    'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*',
    'tcp LISTEN 0 511 127.0.0.1:9099 0.0.0.0:*',
    'tcp LISTEN 0 40 192.168.0.94:80 0.0.0.0:*',
    'tcp LISTEN 0 128 10.9.9.9:5985 0.0.0.0:*',
    'udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*',
    '',
  ].join('\n');
  const ssFile = path.join(T, 'ss.txt'); fs.writeFileSync(ssFile, ssFixture);
  ok('fixture ss: conteggi e classificazioni corrette', () => {
    const res = la.runOnce({ ssFile, scopeObj: { targets: ['192.168.0.94'], exclusions: [] }, noProc: true });
    assert.strictEqual(res.total, 5);
    assert.deepStrictEqual(res.counts, { in_scope: 1, wildcard: 2, local_only: 1, out_of_scope: 1 });
    assert.ok(res.out_of_scope.some((l) => l.addr === '10.9.9.9' && l.port === '5985'));
    assert.ok(res.in_scope.some((l) => l.addr === '192.168.0.94' && l.port === '80'));
  });
  ok('parseSsLine robusto: header saltato, udp UNCONN, ipv6 [::]', () => {
    assert.strictEqual(la.parseSsLine('Netid State Recv-Q Send-Q Local Peer'), null);
    const u = la.parseSsLine('udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*');
    assert.strictEqual(u.port, '68');
    const v6 = la.parseSsLine('tcp LISTEN 0 128 [::]:22 [::]:*');
    assert.strictEqual(v6.addr, '::');
  });
  ok('dedup righe duplicate', () => {
    const res = la.runOnce({ ssFile, scopeObj: { targets: [], exclusions: [] }, noProc: true });
    const keys = new Set(res.in_scope.concat(res.wildcard, res.local_only, res.out_of_scope).map((l) => l.proto + l.addr + l.port));
    assert.strictEqual(keys.size, res.total);
  });
  await okAsync('rilevazione REALE: listener locale 127.0.0.1 appare come local_only (e non in_scope)', async () => {
    const srv = http.createServer(() => {});
    await new Promise((res) => srv.listen(0, '127.0.0.1', res));
    const port = String(srv.address().port);
    try {
      const res = la.runOnce({ scopeObj: { targets: ['192.168.0.94'], exclusions: [] }, noProc: true });
      const hit = res.local_only.find((l) => l.port === port && (l.addr === '127.0.0.1'));
      assert.ok(hit, `listener ${port} non visto: total=${res.total} source=${res.source}`);
    } finally { await new Promise((res) => srv.close(res)); }
  });
  ok('/proc parser: hexToIp e listener reali coerenti con ss (almeno 1)', () => {
    assert.strictEqual(la.hexToIp('0100007F'), '127.0.0.1');
    const procListeners = la.collectFromProc('/proc');
    assert.ok(procListeners.length >= 1, 'nessun listener da /proc?');
  });
  ok('append evidence-index single-writer con numero E- successivo', () => {
    const ei = path.join(T, 'evidence-index.md');
    fs.writeFileSync(ei, '# Evidence Index\n\n| ID | Data | Artefatto | Descrizione | Fonte |\n|---|---|---|---|---|\n| E-007 | 2026-08-26 | `x` | y | z |\n');
    // Percorso CLI reale (append single-writer).
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'listen-audit.js'), '--ss-file', ssFile, '--scope', auditScope, '--no-proc', '--evidence-index', ei], { encoding: 'utf8', timeout: 20000 });
    assert.strictEqual(r.status, 0, r.stderr);
    const txt = fs.readFileSync(ei, 'utf8');
    assert.ok(/^\| E-008 \|/m.test(txt), 'riga E-008 attesa:\n' + txt);
    assert.ok(txt.includes('listen-audit read-only'), 'descrizione assente');
  });
  ok('garanzia read-only: nessuna API kill/signal nel sorgente', () => {
    const src = fs.readFileSync(path.join(WS, 'tools', 'listen-audit.js'), 'utf8');
    assert.ok(!/process\.kill|\.kill\(|SIGTERM|SIGKILL/.test(src), 'il tool non può contenere primitive di kill');
  });

  console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
  fs.rmSync(T, { recursive: true, force: true });
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
