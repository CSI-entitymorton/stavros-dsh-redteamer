#!/usr/bin/env node
// Ondata 6 — suite di regressione (G1→G6):
//   G1 (gate): kind 'pocReplay' + 'chainHead' in CODA al report gate (additivo, SA1 intatto);
//              head-anchor esterno della findings-chain (record-finding: appendHeadAnchor,
//              verifyHeadAnchor, CLI verify-head-anchor) — fail-closed su wipe/truncate/rewrite.
//   G2 (oob):  canale OOB via DNS (node:dgram stdlib): parseDnsQuery fail-closed, risposta A
//              127.0.0.1 TTL 1, listener resistente a datagram malformati, attribuzione marker
//              (hits kind:"dns", CLI hits --marker).
//   G3 (parsers): breadth parser — testssl/whatweb/katana/dirsearch/enum4linux-ng (fail-soft,
//              input malformato → [], nessun throw).
//   G4 (target-model): ingest breadth (testssl→vuln crypto, whatweb→technologies, katana/
//              dirsearch→endpoints, enum4linux-ng→accounts/shares/os) idempotente + snapshot
//              + CLI + fail-closed tool sconosciuto.
//   G5 (planner): WAF rilevato nel grafo → azione nuclei a rate ridotto CODIFICATA (E6
//              applicato), no WAF → nessuna azione http-waf, scope fail-closed invariato.
//   G6 (mcp-bridge): tool read-only Tier 1 (model.snapshot/planner.plan/coverage.gaps):
//              7 tool in tools/list, plan MAI esecutore (nessuna scrittura audit), ping CLI e2e.
// Tutto OFFLINE (solo stdlib), fixture SOLO in mkdtemp, env override ovunque, MAI path reali.
// Il listener DNS dei test è loopback effimero di proprietà del test (porta 0), non è "rete".
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const dgram = require('dgram');
const { spawnSync } = require('child_process');
const assert = require('assert');

let pass = 0; let fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}: ${e.message}`); }
}

const WS = '/home/stavros/Desktop/Redteamingtest';

function cli(file, args, env) {
  return spawnSync(process.execPath, [file, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 30000 });
}

// ─── fixture root ────────────────────────────────────────────────────────────
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'ondata6-'));

// Scope fixture (schema {targets,exclusions}): SOLO target.example, deny-by-default altrove.
const SCOPE = path.join(T, 'scope.json');
fs.writeFileSync(SCOPE, JSON.stringify({ targets: ['target.example'], exclusions: [] }));

// Env con capture a load-time DEVE essere impostato PRIMA dei require:
//   EXP_DIR (poc-replay DEFAULT_EXP_DIR), OOB_DIR (oob OOB_DIR/MARKERS/HITS).
const EXP_DIR = path.join(T, 'exp');
const OOB_DIR = path.join(T, 'oob');
fs.mkdirSync(EXP_DIR, { recursive: true });
fs.mkdirSync(OOB_DIR, { recursive: true });
process.env.EXP_DIR = EXP_DIR;
process.env.OOB_DIR = OOB_DIR;
process.env.SCOPE_JSON = SCOPE;

const gateLib = require(path.join(WS, 'tools', 'gate'));
const prLib = require(path.join(WS, 'tools', 'poc-replay'));
const oobLib = require(path.join(WS, 'tools', 'oob'));
const parsers = require(path.join(WS, 'tools', 'parsers'));
const tm = require(path.join(WS, 'tools', 'target-model'));
const mcpLib = require(path.join(WS, 'tools', 'mcp-bridge'));

// record-finding: env a call-time, ma applicata subito per coerenza con la suite Ondata 4.
const RF_DIR = path.join(T, 'rf');
const FJ = path.join(RF_DIR, 'findings.jsonl');
const ANCH = path.join(RF_DIR, 'findings-head-anchor.jsonl');
const RF_ENV = {
  DSH_WS_ROOT: RF_DIR, ORACLE_ARTIFACTS: path.join(RF_DIR, 'artifacts', 'oracle'),
  FINDINGS_JSONL: FJ, LOOT_JSONL: path.join(RF_DIR, 'loot.jsonl'), FINDINGS_TAB_DB: path.join(RF_DIR, 'tab.db'),
  FINDINGS_HEAD_ANCHOR_FILE: ANCH,
};
Object.assign(process.env, RF_ENV);
const rf = require(path.join(WS, 'tools', 'record-finding'));
const oracle = require(path.join(WS, 'tools', 'oracle'));

// ─── G1 — gate pocReplay/chainHead + head-anchor ─────────────────────────────
console.log('G1 — gate: pocReplay + chainHead (coda additiva, SA1 intatto) + head-anchor');
{
  ok('report gate: SA1 (chain/oracle/evidenceQuote) contiguo invariato + coda Ondata 6', () => {
    const kinds = gateLib.GATES.report.checks.map((c) => c.kind);
    assert.deepStrictEqual(kinds.slice(0, 4), ['findings', 'verify', 'noPending', 'coverage']);
    assert.deepStrictEqual(kinds.slice(4), ['chain', 'oracle', 'evidenceQuote', 'pocReplay', 'chainHead']);
    assert.ok(kinds.slice(4, 7).every((k) => ['chain', 'oracle', 'evidenceQuote'].includes(k)), 'SA1 resta contiguo');
  });

  const vf = path.join(T, 'findings-poc.jsonl');
  fs.writeFileSync(vf, JSON.stringify({ id: 'target.example-sqli-q', status: 'verified', host: 'target.example', title: 'SQLi q' }) + '\n');
  ok('pocReplay: finding verificato SENZA reproducer → FAIL con id in detail (fail-closed)', () => {
    const r = gateLib.checkPocReplay(vf);
    assert.strictEqual(r.ok, false, r.detail);
    assert.ok(r.detail.includes('target.example-sqli-q'), r.detail);
  });
  ok('pocReplay: reproducer exp/<id>.py presente → PASS', () => {
    fs.writeFileSync(path.join(EXP_DIR, 'target.example-sqli-q.py'), '# reproducer stub\n');
    const r = gateLib.checkPocReplay(vf);
    assert.strictEqual(r.ok, true, r.detail);
  });
  ok('pocReplay: nessun finding → vacuous PASS', () => {
    const empty = path.join(T, 'findings-empty.jsonl');
    fs.writeFileSync(empty, '');
    const r = gateLib.checkPocReplay(empty);
    assert.strictEqual(r.ok, true, r.detail);
  });

  // Head-anchor e2e: due finding chained (oracolo meccanico + evidence_quote byte-per-byte).
  const receipt = oracle.writeReceipt({ type: 'http-diff', anchor: 'ondata6 head-anchor test', data: {} });
  assert.ok(receipt.ok, JSON.stringify(receipt));
  const base = {
    severity: 'High', title: 'Ondata6 chain A', host: 'target.example', poc: 'p', status: 'confirmed',
    oracle: { type: 'http-diff', ref: receipt.ref, token: receipt.token },
    evidence_quote: { file: receipt.ref, text: 'ondata6 head-anchor test' },
  };
  const r1 = rf.record(JSON.stringify(base));
  const r2 = rf.record(JSON.stringify({ ...base, title: 'Ondata6 chain B' }));
  assert.ok(r1.ok && r2.ok, JSON.stringify({ r1, r2 }));
  assert.ok(r1.head_anchor && r1.head_anchor.ok === true, 'anchor scritto alla prima append');
  assert.ok(fs.existsSync(ANCH), 'anchor file esiste');

  ok('chainHead: dopo append chained → PASS (anchor allineato)', () => {
    const r = gateLib.checkChainHead();
    assert.strictEqual(r.ok, true, r.detail);
  });
  ok('CLI verify-head-anchor: chain pulita → exit 0', () => {
    const r = cli(path.join(WS, 'tools', 'record-finding.js'), ['verify-head-anchor'], RF_ENV);
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });
  ok('TAMPER mid-line: un byte modificato in riga 1 → chainHead FAIL (chain broken)', () => {
    const lines = fs.readFileSync(FJ, 'utf8').split('\n').filter(Boolean);
    lines[0] = lines[0].replace('"Ondata6 chain A"', '"Ondata6 chain X"');
    fs.writeFileSync(FJ, lines.join('\n') + '\n');
    const r = gateLib.checkChainHead();
    assert.strictEqual(r.ok, false, r.detail);
    assert.ok(/broken/.test(r.detail), r.detail);
  });
  ok('WIPE: findings.jsonl svuotato con anchor presenti → FAIL (no chained lines)', () => {
    fs.writeFileSync(FJ, '');
    const r = rf.verifyHeadAnchor();
    assert.strictEqual(r.ok, false, r.detail);
    assert.ok(/no chained lines/.test(r.detail), r.detail);
  });
  ok('REWRITE: chain rigenerata ex-novo con anchor STALE → FAIL (mismatch, non ok interno)', () => {
    // chain valida ma DIVERSA da quella ancorata: genesis ex-novo + anchor fatto a mano
    // che punta a un head vecchio/fake. Il file è internamente coerente ma non coincide
    // con la storia ancorata → la riscrittura integrale deve essere rilevata.
    const f = { severity: 'Low', title: 'Ondata6 rewrite', host: 'target.example', poc: 'p', status: 'confirmed', ts: new Date().toISOString() };
    const line = rf.buildChainedLine(f, []); // genesis
    fs.writeFileSync(FJ, line + '\n');
    fs.writeFileSync(ANCH, JSON.stringify({ kind: 'findings-head-anchor', ts: new Date().toISOString(), seq: 1, head_sha256: rf.sha256Hex(JSON.stringify({ fake: 'stale-anchor' })) }) + '\n');
    const r = rf.verifyHeadAnchor();
    assert.strictEqual(r.ok, false, r.detail);
    assert.ok(/mismatch|rewritten|truncated|wiped/.test(r.detail), r.detail);
  });
  ok('chainHead: nessun anchor registrato → PASS informativo (retro-compatibile)', () => {
    const r = rf.verifyHeadAnchor({ anchorFile: path.join(T, 'no-anchor.jsonl'), findingsFile: FJ });
    assert.strictEqual(r.ok, true, r.detail);
  });
}

// ─── G2 — DNS OOB ────────────────────────────────────────────────────────────
console.log('G2 — oob: canale DNS OOB (dgram stdlib, loopback effimero)');
{
  // query DNS valida: id 0x1234, RD=1, 1 domanda A IN per <labels>
  function dnsQuery(labels, qtype = 1, id = 0x1234) {
    const head = Buffer.alloc(12);
    head.writeUInt16BE(id, 0); head.writeUInt16BE(0x0100, 2); head.writeUInt16BE(1, 4);
    const parts = [head];
    for (const l of labels) { parts.push(Buffer.from([l.length]), Buffer.from(l, 'ascii')); }
    parts.push(Buffer.from([0]));
    const tail = Buffer.alloc(4);
    tail.writeUInt16BE(qtype, 0); tail.writeUInt16BE(1, 2);
    return Buffer.concat([...parts, tail]);
  }

  ok('parseDnsQuery: query valida → name/qtype/qclass esatti (lowercase)', () => {
    const q = oobLib.parseDnsQuery(dnsQuery(['T0kEn01', 'oob', 'example', 'test']));
    assert.ok(q, 'null inatteso');
    assert.strictEqual(q.name, 't0ken01.oob.example.test');
    assert.strictEqual(q.qtype, 1); assert.strictEqual(q.qclass, 1);
  });
  ok('parseDnsQuery: malformati (corto, qdcount 0, compression pointer, label troncata) → null, mai throw', () => {
    assert.strictEqual(oobLib.parseDnsQuery(Buffer.alloc(5)), null);
    const qd0 = Buffer.alloc(17); qd0.writeUInt16BE(0, 4);
    assert.strictEqual(oobLib.parseDnsQuery(qd0), null);
    const ptr = dnsQuery(['a', 'b']); ptr[12] = 0xc0; // label = compression pointer
    assert.strictEqual(oobLib.parseDnsQuery(ptr), null);
    const trunc = dnsQuery(['a', 'b']); const cut = trunc.slice(0, trunc.length - 6);
    assert.strictEqual(oobLib.parseDnsQuery(cut), null);
  });
  ok('dnsResponseFor: A → ANCOUNT 1, rdata 127.0.0.1, id echo, QR=1; AAAA → ANCOUNT 0', () => {
    const q = oobLib.parseDnsQuery(dnsQuery(['tok', 'oob', 'test']));
    const ra = oobLib.dnsResponseFor(q);
    assert.strictEqual(ra.readUInt16BE(0), 0x1234);
    assert.strictEqual(ra[2], 0x81, 'QR=1');
    assert.strictEqual(ra.readUInt16BE(6), 1, 'ANCOUNT');
    assert.ok(ra.slice(ra.length - 4).equals(Buffer.from([127, 0, 0, 1])), 'rdata 127.0.0.1');
    const q6 = oobLib.parseDnsQuery(dnsQuery(['tok', 'oob', 'test'], 28));
    assert.strictEqual(oobLib.dnsResponseFor(q6).readUInt16BE(6), 0, 'ANCOUNT 0 per AAAA');
  });

  // e2e: listener effimero + marker + query reale + attribuzione hit
  const p = (async () => {
    const sock = await oobLib.createDnsServer(0);
    const port = sock.address().port;
    const token = 'od6tok01';
    oobLib.recordMarker(token, 'http://callback.example/');
    const client = dgram.createSocket('udp4');
    const send = (buf) => new Promise((res, rej) => client.send(buf, port, '127.0.0.1', (e) => (e ? rej(e) : res())));
    const recv = (ms) => new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error('timeout risposta DNS')), ms);
      client.once('message', (m) => { clearTimeout(t); res(m); });
    });
    try {
      client.send(Buffer.from('garbage-not-dns'), port, '127.0.0.1', () => {}); // mai uccidere il listener
      await send(dnsQuery([token, 'oob', 'example', 'test']));
      const resp = await recv(3000);
      assert.strictEqual(resp.readUInt16BE(0), 0x1234, 'id echo');
      assert.strictEqual(resp.readUInt16BE(6), 1, 'ANCOUNT 1');
      assert.ok(resp.slice(resp.length - 4).equals(Buffer.from([127, 0, 0, 1])));
      await send(dnsQuery([token, 'oob', 'example', 'test'], 28, 0x4321)); // AAAA: hit senza A record
      await new Promise((r) => setTimeout(r, 150));
    } finally {
      try { client.close(); } catch {}
      try { sock.close(); } catch {}
    }
    const hits = fs.readFileSync(path.join(OOB_DIR, 'hits.jsonl'), 'utf8').split('\n').filter(Boolean)
      .map((l) => JSON.parse(l)).filter((h) => h.kind === 'dns');
    assert.ok(hits.length >= 2, `attese >=2 hit dns, trovate ${hits.length}`);
    const last = hits[hits.length - 1];
    assert.strictEqual(last.marker, token, 'attribuzione marker');
    assert.ok(last.qname.includes(token), 'qname contiene il token');
    assert.strictEqual(last.source_ip, '127.0.0.1');
    const c = cli(path.join(WS, 'tools', 'oob.js'), ['hits', '--marker', token, '--tail', '5'], { OOB_DIR });
    assert.strictEqual(c.status, 0, c.stderr);
    const out = JSON.parse(c.stdout);
    assert.ok(out.matched >= 1, `CLI hits --marker matched=${out.matched}`);
  })();
  // ok() sync non cattura promise: il conteggio di questo caso avviene nella catena qui sotto.
  p.then(() => { pass++; console.log('  PASS DNS e2e: listener effimero, risposta A, marker attribuito (kind:"dns"), CLI hits --marker'); })
    .catch((e) => { fail++; console.log(`  FAIL DNS e2e: ${e.message}`); });
}

// ─── G3 — parser breadth ─────────────────────────────────────────────────────
console.log('G3 — parsers breadth (testssl/whatweb/katana/dirsearch/enum4linux-ng)');
{
  ok('parseTestsslJson: severità mappate, cve/host/port, NDJSON accettato, malformato → []', () => {
    const recs = [
      { id: 'TLS1', severity: 'CRITICAL', finding: 'TLS 1.0 offered', cve: 'CVE-2020-1', target: 'target.example:443', port: '443' },
      { id: 'OK-1', severity: 'OK', finding: 'fine' },
    ];
    let r = parsers.parseTestsslJson(JSON.stringify(recs));
    assert.strictEqual(r.length, 2);
    assert.deepStrictEqual([r[0].severity, r[1].severity], ['critical', 'info']);
    assert.strictEqual(r[0].host, 'target.example'); assert.strictEqual(r[0].port, 443);
    assert.strictEqual(r[0].cve, 'CVE-2020-1');
    r = parsers.parseTestsslJson(JSON.stringify(recs[0]) + '\n' + JSON.stringify(recs[1]));
    assert.strictEqual(r.length, 2, 'NDJSON');
    assert.deepStrictEqual(parsers.parseTestsslJson('not-json{'), []);
    assert.deepStrictEqual(parsers.parseTestsslJson(''), []);
  });
  ok('parseWhatwebJson: plugins → tech[{name,version}] (array→primo), target mancante → skip', () => {
    const r = parsers.parseWhatwebJson(JSON.stringify([
      { target: 'http://target.example/', http_status: 200, plugins: { CloudFlare: { version: ['2026.1', 'x'] }, Nginx: {} } },
      { plugins: { Orphan: {} } },
    ]));
    assert.strictEqual(r.length, 1);
    assert.deepStrictEqual(r[0].tech, [{ name: 'CloudFlare', version: '2026.1' }, { name: 'Nginx', version: null }]);
    assert.strictEqual(r[0].status, 200);
  });
  ok('parseKatanaJsonl: request.endpoint → url, method upper, endpoint mancante → skip', () => {
    const r = parsers.parseKatanaJsonl(JSON.stringify({ request: { method: 'get', endpoint: 'http://target.example/login' }, response: { status_code: 200 } })
      + '\n' + JSON.stringify({ request: {}, response: {} }));
    assert.deepStrictEqual(r, [{ method: 'GET', url: 'http://target.example/login', status: 200 }]);
  });
  ok('parseDirsearchJson: results[] e forma target+path, content-length numerico', () => {
    const r = parsers.parseDirsearchJson(JSON.stringify({ results: [
      { url: 'http://target.example/admin', status: 200, 'content-length': '42' },
      { target: 'http://target.example/', path: 'backup.zip', status: 403 },
    ] }));
    assert.deepStrictEqual(r, [
      { url: 'http://target.example/admin', status: 200, length: 42 },
      { url: 'http://target.example/backup.zip', status: 403, length: null },
    ]);
  });
  ok('parseEnum4linuxNgJson: singolo record → users/shares/os/workgroup; forme improprie → []', () => {
    const rec = { target: 'target.example', workgroup: 'LAB', smb: { native_os: 'Windows Server 2019' },
      users: [{ username: 'svc-backup' }, { username: ' ' }],
      shares: [{ name: 'IPC$', type: 'IPC', comment: 'c', ops4_status: 'READABLE' }] };
    const r = parsers.parseEnum4linuxNgJson(JSON.stringify(rec));
    assert.strictEqual(r.length, 1);
    assert.deepStrictEqual(r[0].users, [{ username: 'svc-backup' }]);
    assert.strictEqual(r[0].os, 'Windows Server 2019');
    assert.deepStrictEqual(r[0].shares, [{ name: 'IPC$', type: 'IPC', comment: 'c', access: 'READABLE' }]);
    assert.deepStrictEqual(parsers.parseEnum4linuxNgJson(JSON.stringify([rec, rec])), [], 'array multi-record rifiutato');
    assert.deepStrictEqual(parsers.parseEnum4linuxNgJson('{"nope":1}'), []);
  });
}

// ─── G4 — target-model breadth ingest ────────────────────────────────────────
console.log('G4 — target-model: ingest breadth + snapshot + CLI');
{
  const dbPath = path.join(T, 'tm', 'state.db');
  const db = tm.open(dbPath);
  try {
    const testssl = JSON.stringify([{ id: 'TLS1', severity: 'HIGH', finding: 'TLS 1.0', cve: 'CVE-2020-1', target: 'target.example:443', port: 443 }]);
    const whatweb = JSON.stringify([{ target: 'http://target.example/', http_status: 200, plugins: { CloudFlare: { version: ['2026.1'] } } }]);
    const katana = JSON.stringify({ request: { method: 'GET', endpoint: 'http://target.example/login' }, response: { status_code: 200 } });
    const dirsearch = JSON.stringify({ results: [{ url: 'http://target.example/admin', status: 200 }] });
    const enum4 = JSON.stringify({ target: 'target.example', workgroup: 'LAB', smb: { native_os: 'Windows Server 2019' },
      users: [{ username: 'svc-backup' }], shares: [{ name: 'IPC$', type: 'IPC', comment: 'c', ops4_status: 'READABLE' }] });

    ok('ingest testssl → vuln class "crypto", tcp://host:443; re-ingest idempotente', () => {
      const a = tm.ingest(db, 'testssl', testssl, {});
      assert.ok(a.ok, JSON.stringify(a)); assert.strictEqual(a.counts.vulns, 1);
      const b = tm.ingest(db, 'testssl', testssl, {});
      assert.ok(b.ok && b.counts.vulns === 1, `idempotenza: ${JSON.stringify(b)}`);
      const v = tm.listVulns(db);
      assert.strictEqual(v.length, 1);
      assert.strictEqual(v[0].class, 'crypto'); assert.strictEqual(v[0].severity, 'high');
      assert.strictEqual(v[0].url, 'tcp://target.example:443'); assert.strictEqual(v[0].cve, 'CVE-2020-1');
    });
    ok('ingest whatweb → technologies + endpoint fingerprintato (idempotente)', () => {
      const a = tm.ingest(db, 'whatweb', whatweb, {});
      assert.ok(a.ok && a.counts.technologies === 1, JSON.stringify(a));
      const b = tm.ingest(db, 'whatweb', whatweb, {});
      assert.ok(b.ok && b.counts.technologies === 1, 'idempotente');
      const t = tm.listTechnologies(db);
      assert.strictEqual(t.length, 1);
      assert.strictEqual(t[0].name, 'CloudFlare'); assert.strictEqual(t[0].version, '2026.1'); assert.strictEqual(t[0].source, 'whatweb');
    });
    ok('ingest katana+dirsearch → endpoints dedotti (crawl/dir-bust)', () => {
      assert.ok(tm.ingest(db, 'katana', katana, {}).ok);
      const a = tm.ingest(db, 'dirsearch', dirsearch, {});
      assert.ok(a.ok && a.counts.endpoints === 1, JSON.stringify(a));
      const snap = tm.snapshot(db);
      const urls = snap.targets.flatMap((t) => t.endpoints.map((e) => e.url));
      assert.ok(urls.includes('http://target.example/login') && urls.includes('http://target.example/admin'), JSON.stringify(urls));
    });
    ok('ingest enum4linux-ng → host os + accounts + shares + endpoint smb://', () => {
      const a = tm.ingest(db, 'enum4linux-ng', enum4, {});
      assert.ok(a.ok, JSON.stringify(a));
      assert.strictEqual(a.counts.accounts, 1); assert.strictEqual(a.counts.shares, 1);
      assert.strictEqual(tm.listAccounts(db)[0].username, 'svc-backup');
      const sh = tm.listShares(db)[0];
      assert.strictEqual(sh.name, 'IPC$'); assert.strictEqual(sh.access, 'READABLE');
      const snap = tm.snapshot(db);
      const t0 = snap.targets.find((t) => t.host === 'target.example');
      assert.strictEqual(t0.accounts.length, 1);
      assert.strictEqual(t0.shares[0].name, 'IPC$');
      assert.strictEqual(t0.technologies[0].name, 'CloudFlare');
      assert.ok(t0.hosts.some((h) => (h.os || '').includes('Windows Server 2019')), JSON.stringify(t0.hosts));
      assert.ok(t0.endpoints.some((e) => e.url === 'smb://target.example/IPC$'), 'endpoint smb');
    });
    ok('toEntities: entità del grafo restano valide vs taxonomy (nessuna spuria)', () => {
      const ents = tm.toEntities(db);
      assert.ok(Array.isArray(ents.entities) && ents.entities.length > 0, JSON.stringify(ents));
      assert.ok(ents.entities.every((e) => e && e.entityType), JSON.stringify(ents.entities[0]));
      assert.strictEqual(ents.invalid.length, 0, JSON.stringify(ents.invalid));
    });
    ok('fail-closed: tool sconosciuto → ok:false; input malformato → zero righe senza throw', () => {
      const bad = tm.ingest(db, 'evil-tool', '{}', {});
      assert.strictEqual(bad.ok, false);
      const g = tm.ingest(db, 'testssl', 'garbage{{', {});
      assert.ok(g.ok && g.counts.vulns === 0, JSON.stringify(g));
      assert.strictEqual(tm.listVulns(db).length, 1, 'nessuna riga spuria');
    });
    ok('CLI: tech/accounts/shares/snapshot con STATE_DB → JSON validi', () => {
      for (const cmd of ['tech', 'accounts', 'shares', 'snapshot']) {
        const r = cli(path.join(WS, 'tools', 'target-model.js'), [cmd], { STATE_DB: dbPath });
        assert.strictEqual(r.status, 0, `${cmd}: ${r.stderr}`);
        const parsed = JSON.parse(r.stdout);
        assert.ok(Array.isArray(parsed) || (cmd === 'snapshot' && Array.isArray(parsed.targets)), cmd);
      }
    });
  } finally { try { db.close(); } catch {} }
}

// ─── G5 — planner WAF-aware ──────────────────────────────────────────────────
console.log('G5 — next-actions: WAF rilevato → nuclei a rate ridotto (E6 codificato)');
{
  const mkSnap = (technologies, vulns) => ({
    generated_at: '2026-08-27T00:00:00.000Z',
    targets: [{
      host: 'target.example',
      hosts: [{ address: 'target.example', alive: 1, ports: [{ port: 80, state: 'open', service: 'http' }] }],
      endpoints: [{ method: 'GET', url: 'http://target.example/', tech: technologies.map((t) => t.name).join(',') || null, auth: false }],
      vulns, creds: [], technologies,
    }],
  });
  const wafTech = [{ host: 'target.example', url: 'http://target.example/', name: 'CloudFlare', version: '2026.1', source: 'whatweb' }];
  const allow = () => ({ ok: true, reason: 'test' });

  ok('WAF nel grafo → azione surface "http-waf", nuclei -rl 5, tier active, NON opt-in', () => {
    const p = require(path.join(WS, 'tools', 'next-actions')).plan(mkSnap(wafTech, []), { inScope: allow });
    const waf = p.actions.filter((a) => a.surface === 'http-waf');
    assert.strictEqual(waf.length, 1, JSON.stringify(p.actions.map((a) => a.surface)));
    assert.ok(/nuclei .*-rl 5/.test(waf[0].cmd), waf[0].cmd);
    assert.ok(/run\.js/.test(waf[0].cmd), 'sempre via entry point guardato: ' + waf[0].cmd);
    assert.strictEqual(waf[0].tier, 'active');
    assert.strictEqual(waf[0].requires_optin, false);
    assert.strictEqual(waf[0].covered, false);
  });
  ok('NESSUN WAF → nessuna azione http-waf (nessuna spuria)', () => {
    const p = require(path.join(WS, 'tools', 'next-actions')).plan(mkSnap([{ name: 'Nginx' }].map((t) => ({ host: 'target.example', ...t })), []), { inScope: allow });
    assert.strictEqual(p.actions.filter((a) => a.surface === 'http-waf').length, 0);
  });
  ok('WAF + vuln già presente sull endpoint → azione coperta (covered=true)', () => {
    const p = require(path.join(WS, 'tools', 'next-actions')).plan(
      mkSnap(wafTech, [{ host: 'target.example', url: 'http://target.example/', class: 'sqli', severity: 'high' }]), { inScope: allow });
    const waf = p.actions.find((a) => a.surface === 'http-waf');
    assert.ok(waf && waf.covered === true, JSON.stringify(waf));
  });
  ok('scope fail-closed INVARIATO: inScope falso → tutte blocked (il WAF non bypassa)', () => {
    const p = require(path.join(WS, 'tools', 'next-actions')).plan(mkSnap(wafTech, []), { inScope: () => ({ ok: false, reason: 'out' }) });
    assert.ok(p.actions.length > 0);
    assert.ok(p.actions.every((a) => a.blocked === true), 'azione non bloccata trovata');
  });
}

// ─── G6 — mcp-bridge read-only Tier 1 ────────────────────────────────────────
console.log('G6 — mcp-bridge: model.snapshot / planner.plan / coverage.gaps (read-only)');
{
  const dbPath = path.join(T, 'tm', 'state.db'); // riusa la fixture G4 (popolata)
  const AUDIT_GUARD = path.join(T, 'audit-guard.jsonl');
  process.env.STATE_DB = dbPath;
  process.env.FINDINGS_JSONL = path.join(T, 'gaps', 'findings.jsonl'); // assente → gaps vuoti
  process.env.RUN_AUDIT_FILE = AUDIT_GUARD;

  ok('tools/list: 7 tool, 3 nuovi read-only in whitelist', () => {
    const list = mcpLib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }));
    assert.deepStrictEqual(list.result.tools.map((t) => t.name),
      ['scope.check', 'run.dryRun', 'gate.status', 'model.snapshot', 'planner.plan', 'coverage.gaps', 'system.info']);
    assert.ok(list.result.tools.every((t) => !/run|--yes/i.test(t.name + ' ' + (t.description || '')) || /never|dry-run|read-only/i.test(t.description || '')),
      'nessun tool descritto come esecutore');
  });
  ok('model.snapshot: asset graph della fixture, sola lettura', () => {
    const r = mcpLib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'model.snapshot', arguments: {} } }));
    const snap = JSON.parse(r.result.content[0].text);
    assert.ok(Array.isArray(snap.targets) && snap.targets.some((t) => t.host === 'target.example'), r.result.content[0].text.slice(0, 200));
  });
  ok('planner.plan: DRY-RUN (azioni+summary), NESSUNA esecuzione (audit non creato)', () => {
    const r = mcpLib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'planner.plan', arguments: {} } }));
    const plan = JSON.parse(r.result.content[0].text);
    assert.ok(Array.isArray(plan.actions) && plan.summary, r.result.content[0].text.slice(0, 200));
    assert.ok(plan.actions.every((a) => typeof a.cmd === 'string'), 'azioni solo piano');
    assert.strictEqual(fs.existsSync(AUDIT_GUARD), false, 'audit creato: il piano ha ESEGUITO qualcosa');
  });
  ok('coverage.gaps: misura senza esecuzione (findings assenti → JSON valido)', () => {
    const r = mcpLib.handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'coverage.gaps', arguments: {} } }));
    const parsed = JSON.parse(r.result.content[0].text);
    assert.ok(Array.isArray(parsed), r.result.content[0].text.slice(0, 200));
  });
  ok('ping CLI e2e: initialize + tools/list → ok:true, 7 tool', () => {
    const r = cli(path.join(WS, 'tools', 'mcp-bridge.js'), ['ping'], { STATE_DB: dbPath, SCOPE_JSON: SCOPE });
    assert.strictEqual(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.ok, true, r.stdout);
    assert.strictEqual(out.tools.length, 7);
  });
}

console.log(`\nRisultato: ${pass} pass, ${fail} fail`);
process.exitCode = fail ? 1 : 0;
