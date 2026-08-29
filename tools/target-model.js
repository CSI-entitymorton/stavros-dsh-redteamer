#!/usr/bin/env node
// Tier 1-A — Target model: the harness's normalized "asset graph".
//
// This is the GLUE that was missing: it wires the pure parsers (tools/parsers.js) to the
// structured store (tools/state.js) and to the typed taxonomy (tools/entity-taxonomy.js).
// Third-party tool output (nmap -oX, httpx -json, ffuf -json, nuclei -jsonl, netexec) is
// normalized ONCE and upserted into a single queryable model of the target, so the agent
// reasons over host/port/service/vuln/cred STATE instead of re-parsing raw text each time.
//
// Design contract (inherited from the ondate discipline):
//   - Zero external deps: node:sqlite (via state.js) + stdlib only. No network, no subprocess.
//   - ADDITIVE: reuses state.js's targets/hosts/ports/endpoints tables unchanged; the two new
//     tables (vulns, credentials) are created with CREATE TABLE IF NOT EXISTS, so an existing
//     state.db keeps working. No existing schema/row is ever mutated destructively.
//   - Fail-closed: a malformed blob makes the parser return []/null (never throws) -> zero
//     upserts. An unknown tool returns {ok:false,...}, never guesses.
//   - Idempotent: re-ingesting the same output upserts (no duplicate rows), so it is safe to
//     re-run a step. UNIQUE constraints back this.
//   - It NEVER touches scope-guard / enforce / gate / oracle: this is a read-model built FROM
//     already-authorized-and-run tool output. It grants no capability and bypasses nothing.
//
// CLI:
//   node tools/target-model.js ingest <tool> <file> [--target <host>]   # tool: nmap|httpx|ffuf|nuclei|netexec
//   node tools/target-model.js snapshot                                 # whole model as JSON
//   node tools/target-model.js hosts | services | vulns | creds         # focused views (JSON)
//   node tools/target-model.js entities                                 # typed entities (validated) as JSON
//
// Env: STATE_DB (inherited from state.js) — point it at a mkdtemp file in tests, never the real db.
'use strict';

const fs = require('fs');
const path = require('path');
const state = require('./state');
const parsers = require('./parsers');
const coverage = require('./coverage');

const now = () => new Date().toISOString();

// The tools we know how to normalize into the model. Anything else is refused fail-closed.
// Ondata 6 breadth: testssl (TLS/crypto), whatweb (tech/WAF), katana (crawl), dirsearch
// (dir-bust), enum4linux-ng (SMB accounts/shares). Same fail-closed dispatch as the originals.
const KNOWN_TOOLS = ['nmap', 'httpx', 'ffuf', 'nuclei', 'netexec', 'testssl', 'whatweb', 'katana', 'dirsearch', 'enum4linux-ng'];

// ------------------------------------------------------------------ store bootstrap
// Additive tables. state.open() creates the base schema; we layer vulns + credentials on top.
// IF NOT EXISTS keeps this safe on a pre-existing state.db.
function ensureExtraSchema(db) {
  db.exec(`
CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER REFERENCES targets(id),
  host TEXT,
  url TEXT,
  class TEXT,
  template_id TEXT,
  severity TEXT,
  cve TEXT,
  source TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(host, url, template_id, class)
);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT,
  service TEXT,
  username TEXT,
  secret TEXT,
  kind TEXT NOT NULL DEFAULT 'password',
  source TEXT NOT NULL,
  validated INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(host, username, secret)
);
CREATE TABLE IF NOT EXISTS technologies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT,
  url TEXT,
  name TEXT NOT NULL,
  version TEXT,
  source TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(host, url, name)
);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT,
  username TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(host, username)
);
CREATE TABLE IF NOT EXISTS shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT,
  name TEXT NOT NULL,
  type TEXT,
  comment TEXT,
  access TEXT,
  source TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(host, name)
);`);
}

// open(file) — a state.js DB handle with the extra tables guaranteed present.
function open(file) {
  const db = state.open(file);
  ensureExtraSchema(db);
  return db;
}

// ------------------------------------------------------------------ small helpers
function hostnameOf(u) {
  if (!u) return null;
  try {
    return new URL(String(u).includes('://') ? u : 'http://' + u).hostname || null;
  } catch {
    return null;
  }
}
function portOf(u) {
  try {
    const parsed = new URL(String(u).includes('://') ? u : 'http://' + u);
    if (parsed.port) return Number(parsed.port);
    return parsed.protocol === 'https:' ? 443 : 80;
  } catch {
    return null;
  }
}
function readLines(raw) {
  return String(raw == null ? '' : raw).split(/\r?\n/).filter((l) => l.trim());
}

function upsertVuln(db, v) {
  const ts = now();
  db.prepare(
    'INSERT INTO vulns (target_id, host, url, class, template_id, severity, cve, source, first_seen, last_seen) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(host, url, template_id, class) DO UPDATE SET severity = COALESCE(excluded.severity, vulns.severity), ' +
    'cve = COALESCE(excluded.cve, vulns.cve), last_seen = excluded.last_seen'
  ).run(v.target_id || null, v.host || null, v.url || null, v.class || null, v.template_id || null,
    v.severity || null, v.cve || null, v.source, ts, ts);
}
function upsertCred(db, c) {
  const ts = now();
  db.prepare(
    'INSERT INTO credentials (host, service, username, secret, kind, source, validated, first_seen, last_seen) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(host, username, secret) DO UPDATE SET service = COALESCE(excluded.service, credentials.service), ' +
    'validated = MAX(excluded.validated, credentials.validated), last_seen = excluded.last_seen'
  ).run(c.host || null, c.service || null, c.username || null, c.secret || null,
    c.kind || 'password', c.source, c.validated ? 1 : 0, ts, ts);
}

// Ondata 6 breadth upserts (additive; UNIQUE constraints keep re-ingest idempotent).
function upsertTechnology(db, t) {
  const ts = now();
  db.prepare(
    'INSERT INTO technologies (host, url, name, version, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(host, url, name) DO UPDATE SET version = COALESCE(excluded.version, technologies.version), last_seen = excluded.last_seen'
  ).run(t.host || null, t.url || null, t.name, t.version || null, t.source, ts, ts);
}
function upsertAccount(db, a) {
  const ts = now();
  db.prepare(
    'INSERT INTO accounts (host, username, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) ' +
    'ON CONFLICT(host, username) DO UPDATE SET source = excluded.source, last_seen = excluded.last_seen'
  ).run(a.host || null, a.username, a.source, ts, ts);
}
function upsertShare(db, s) {
  const ts = now();
  db.prepare(
    'INSERT INTO shares (host, name, type, comment, access, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(host, name) DO UPDATE SET type = COALESCE(excluded.type, shares.type), ' +
    'comment = COALESCE(excluded.comment, shares.comment), access = COALESCE(excluded.access, shares.access), last_seen = excluded.last_seen'
  ).run(s.host || null, s.name, s.type || null, s.comment || null, s.access || null, s.source, ts, ts);
}

// ------------------------------------------------------------------ per-tool ingest
// Each returns a counts object; parsers already fail-soft, so bad input => all-zero counts.

function ingestNmap(db, raw, opts) {
  const hosts = parsers.parseNmapXml(raw);
  let h = 0; let p = 0;
  for (const host of hosts) {
    const tHost = opts.target || host.address;
    const tid = state.upsertTarget(db, tHost);
    const hid = state.upsertHost(db, tid, host.address, { hostname: host.hostname, os: host.os, alive: 1 });
    h++;
    for (const port of host.ports || []) {
      state.upsertPort(db, hid, port.port, port.protocol, port.service, port.version, port.state);
      p++;
    }
  }
  return { hosts: h, ports: p };
}

function ingestHttpx(db, raw, opts) {
  let e = 0; let h = 0;
  for (const line of readLines(raw)) {
    const r = parsers.parseHttpxJson(line);
    if (!r) continue;
    const host = opts.target || hostnameOf(r.url) || r.host;
    if (!host) continue;
    const tid = state.upsertTarget(db, host);
    // If httpx resolved an IP + the URL carries a port, record the host/port too.
    if (r.host) {
      const hid = state.upsertHost(db, tid, r.host, { hostname: hostnameOf(r.url), alive: 1 });
      const port = portOf(r.url);
      if (port) { state.upsertPort(db, hid, port, 'tcp', 'http', r.webserver, 'open'); }
      h++;
    }
    state.upsertEndpoint(db, tid, 'GET', r.url, { tech: (r.tech || []).join(',') || r.webserver || null, auth: 0 });
    e++;
  }
  return { endpoints: e, hosts: h };
}

function ingestFfuf(db, raw, opts) {
  let e = 0;
  for (const line of readLines(raw)) {
    const r = parsers.parseFfufJson(line);
    if (!r) continue;
    const host = opts.target || hostnameOf(r.url);
    if (!host) continue;
    const tid = state.upsertTarget(db, host);
    state.upsertEndpoint(db, tid, 'GET', r.url, { auth: 0 });
    e++;
  }
  return { endpoints: e };
}

function ingestNuclei(db, raw, opts) {
  let v = 0;
  for (const line of readLines(raw)) {
    const r = parsers.parseNucleiJsonl(line);
    if (!r) continue;
    const host = opts.target || r.host || hostnameOf(r.url);
    const tid = host ? state.upsertTarget(db, host) : null;
    // Classify into a coverage CLASS from the human-readable signal; classOf falls back to
    // 'other' which is NOT a coverage class, so such rows still record but yield no Vuln entity.
    const cls = coverage.classOf({ title: r.name, type: (r.tags || []).join(' '), cwe: (r.cve || []).join(' ') });
    upsertVuln(db, {
      target_id: tid, host: host || null, url: r.url || null, class: cls,
      template_id: r.template_id, severity: r.severity, cve: (r.cve || []).join(',') || null, source: 'nuclei',
    });
    v++;
  }
  return { vulns: v };
}

// Ondata 6 breadth ingest — each returns counts; parsers fail-soft, so bad input → zero rows.

function ingestTestssl(db, raw, opts) {
  let v = 0;
  for (const r of parsers.parseTestsslJson(raw)) {
    const host = opts.target || r.host;
    if (!host) continue;
    const tid = state.upsertTarget(db, host);
    // url must be stable & non-null: SQLite UNIQUE treats NULLs as distinct → re-ingest would
    // duplicate rows. tcp://host:port (443 default) keeps the crypto rows idempotent.
    upsertVuln(db, {
      target_id: tid, host, url: `tcp://${r.host || host}:${r.port || 443}`,
      class: 'crypto', template_id: r.id, severity: r.severity, cve: r.cve, source: 'testssl',
    });
    v++;
  }
  return { vulns: v };
}

function ingestWhatweb(db, raw, opts) {
  let t = 0;
  for (const r of parsers.parseWhatwebJson(raw)) {
    const host = opts.target || hostnameOf(r.target);
    if (!host) continue;
    const tid = state.upsertTarget(db, host);
    for (const p of r.tech || []) {
      upsertTechnology(db, { host, url: r.target, name: p.name, version: p.version, source: 'whatweb' });
      t++;
    }
    // The fingerprinted URL is itself an endpoint worth tracking (upsert = idempotent).
    state.upsertEndpoint(db, tid, 'GET', r.target, { tech: (r.tech || []).map((p) => p.name).join(',') || null, auth: 0 });
  }
  return { technologies: t };
}

function ingestCrawl(db, raw, opts, tool) {
  let e = 0;
  const records = tool === 'dirsearch' ? parsers.parseDirsearchJson(raw) : parsers.parseKatanaJsonl(raw);
  for (const r of records) {
    const host = opts.target || hostnameOf(r.url);
    if (!host) continue;
    const tid = state.upsertTarget(db, host);
    state.upsertEndpoint(db, tid, r.method || 'GET', r.url, { auth: 0 });
    e++;
  }
  return { endpoints: e };
}

function ingestEnum4linuxNg(db, raw, opts) {
  let h = 0; let a = 0; let s = 0;
  for (const r of parsers.parseEnum4linuxNgJson(raw)) {
    const host = opts.target || r.host;
    if (!host) continue;
    const tid = state.upsertTarget(db, host);
    state.upsertHost(db, tid, host, { os: r.os, alive: 1 });
    h++;
    for (const u of r.users || []) { upsertAccount(db, { host, username: u.username, source: 'enum4linux-ng' }); a++; }
    for (const sh of r.shares || []) {
      upsertShare(db, { host, name: sh.name, type: sh.type, comment: sh.comment, access: sh.access, source: 'enum4linux-ng' });
      state.upsertEndpoint(db, tid, 'SMB', `smb://${host}/${sh.name}`, { auth: 0 });
      s++;
    }
  }
  return { hosts: h, accounts: a, shares: s };
}

function ingestNetexec(db, raw, opts) {
  const hosts = parsers.parseNetexec(raw);
  let h = 0; let c = 0; let s = 0;
  for (const host of hosts) {
    const tHost = opts.target || host.address;
    const tid = state.upsertTarget(db, tHost);
    state.upsertHost(db, tid, host.address, { hostname: host.hostname, os: host.os, alive: 1 });
    h++;
    for (const share of host.shares || []) {
      state.upsertEndpoint(db, tid, 'SMB', `smb://${host.address}/${share}`, { auth: 0 });
      s++;
    }
    for (const cred of host.creds || []) {
      // parseNetexec yields "DOMAIN\\user:pass" or "user:pass".
      const idx = cred.lastIndexOf(':');
      if (idx <= 0) continue;
      upsertCred(db, { host: host.address, service: 'smb', username: cred.slice(0, idx), secret: cred.slice(idx + 1), kind: 'password', source: 'netexec', validated: 1 });
      c++;
    }
  }
  return { hosts: h, shares: s, creds: c };
}

// ingest(db, tool, raw, opts) — dispatch by tool. Never throws on content; returns
// {ok:true, tool, counts} or {ok:false, reason} for an unknown tool.
function ingest(db, tool, raw, opts) {
  opts = opts || {};
  const t = String(tool || '').toLowerCase();
  if (!KNOWN_TOOLS.includes(t)) return { ok: false, reason: `unknown tool "${tool}" (known: ${KNOWN_TOOLS.join('/')})` };
  let counts;
  switch (t) {
    case 'nmap': counts = ingestNmap(db, raw, opts); break;
    case 'httpx': counts = ingestHttpx(db, raw, opts); break;
    case 'ffuf': counts = ingestFfuf(db, raw, opts); break;
    case 'nuclei': counts = ingestNuclei(db, raw, opts); break;
    case 'netexec': counts = ingestNetexec(db, raw, opts); break;
    case 'testssl': counts = ingestTestssl(db, raw, opts); break;
    case 'whatweb': counts = ingestWhatweb(db, raw, opts); break;
    case 'katana': counts = ingestCrawl(db, raw, opts, 'katana'); break;
    case 'dirsearch': counts = ingestCrawl(db, raw, opts, 'dirsearch'); break;
    case 'enum4linux-ng': counts = ingestEnum4linuxNg(db, raw, opts); break;
    default: return { ok: false, reason: `unknown tool "${tool}"` };
  }
  return { ok: true, tool: t, counts };
}

// ------------------------------------------------------------------ query / views
function listVulns(db, targetId) {
  return targetId != null
    ? db.prepare('SELECT * FROM vulns WHERE target_id = ? ORDER BY host, url').all(targetId)
    : db.prepare('SELECT * FROM vulns ORDER BY host, url').all();
}
function listCreds(db, host) {
  return host
    ? db.prepare('SELECT * FROM credentials WHERE host = ? ORDER BY username').all(host)
    : db.prepare('SELECT * FROM credentials ORDER BY host, username').all();
}

// Ondata 6 breadth views (additive; host-filtered like listCreds when a host is given).
function listTechnologies(db, host) {
  return host
    ? db.prepare('SELECT * FROM technologies WHERE host = ? ORDER BY name').all(host)
    : db.prepare('SELECT * FROM technologies ORDER BY host, name').all();
}
function listAccounts(db, host) {
  return host
    ? db.prepare('SELECT * FROM accounts WHERE host = ? ORDER BY username').all(host)
    : db.prepare('SELECT * FROM accounts ORDER BY host, username').all();
}
function listShares(db, host) {
  return host
    ? db.prepare('SELECT * FROM shares WHERE host = ? ORDER BY name').all(host)
    : db.prepare('SELECT * FROM shares ORDER BY host, name').all();
}

// snapshot(db) — the whole model as one plain object. This is what the (Tier 1-B)
// finding-driven orchestrator reads to decide the next action.
function snapshot(db) {
  const out = { generated_at: now(), targets: [] };
  for (const t of state.listTargets(db)) {
    const hosts = state.listHosts(db, t.id).map((h) => ({
      address: h.address, hostname: h.hostname, os: h.os, alive: !!h.alive,
      ports: state.listPorts(db, h.id).map((p) => ({
        port: p.port, protocol: p.protocol, service: p.service, version: p.version, state: p.state,
      })),
    }));
    out.targets.push({
      host: t.host,
      hosts,
      endpoints: state.listEndpoints(db, t.id).map((e) => ({ method: e.method, url: e.url, tech: e.tech, auth: !!e.auth })),
      vulns: listVulns(db, t.id).map((v) => ({ host: v.host, url: v.url, class: v.class, template_id: v.template_id, severity: v.severity, cve: v.cve, source: v.source })),
      creds: listCreds(db).filter((c) => hosts.some((h) => h.address === c.host)).map((c) => ({ host: c.host, service: c.service, username: c.username, kind: c.kind, validated: !!c.validated, source: c.source })),
      technologies: listTechnologies(db).filter((r) => hosts.some((h) => h.address === r.host) || r.host === t.host).map((r) => ({ host: r.host, url: r.url, name: r.name, version: r.version, source: r.source })),
      accounts: listAccounts(db).filter((r) => hosts.some((h) => h.address === r.host) || r.host === t.host).map((r) => ({ host: r.host, username: r.username, source: r.source })),
      shares: listShares(db).filter((r) => hosts.some((h) => h.address === r.host) || r.host === t.host).map((r) => ({ host: r.host, name: r.name, type: r.type, comment: r.comment, access: r.access, source: r.source })),
    });
  }
  return out;
}

// ------------------------------------------------------------------ typed entities
// Build Target/Port/Service/Vuln entities matching docs/entity-taxonomy.yaml, so coverage.js
// (coveredClassesFromEntities) and the completeness loop consume ONE typed language. Every
// entity is validated fail-closed against the taxonomy; anything invalid is dropped, never
// emitted (no spurious entities — same rule entity-taxonomy.js enforces on the memory graph).
function toEntities(db, tax) {
  const et = require('./entity-taxonomy');
  tax = tax || et.loadTaxonomy();
  const entities = [];
  const invalid = [];
  const push = (e) => {
    const v = et.validateEntity(e, tax); // null == valid; string/object == rejection reason
    if (v === null) entities.push(e);
    else invalid.push({ entity: e, reason: v });
  };

  for (const t of state.listTargets(db)) {
    push({ entityType: 'Target', id: t.host, name: t.host });
    for (const h of state.listHosts(db, t.id)) {
      for (const p of state.listPorts(db, h.id)) {
        const portId = `${h.address}:${p.port}/${p.protocol}`;
        push({ entityType: 'Port', id: portId, target_ref: t.host, port: p.port, protocol: p.protocol, state: p.state });
        if (p.service) {
          push({ entityType: 'Service', id: `${portId}#svc`, port_ref: portId, name: p.service, version: p.version || undefined });
        }
      }
    }
    for (const v of listVulns(db, t.id)) {
      if (!v.class || !coverage.CLASSES.includes(v.class)) continue; // only real coverage classes
      push({ entityType: 'Vuln', id: `${v.host || v.url || t.host}:${v.template_id || v.class}`, surface_ref: v.url || v.host || t.host, class: v.class });
    }
  }
  return { entities, invalid };
}

module.exports = {
  open, ensureExtraSchema, ingest, snapshot, toEntities,
  listVulns, listCreds, listTechnologies, listAccounts, listShares,
  upsertVuln, upsertCred, upsertTechnology, upsertAccount, upsertShare,
  KNOWN_TOOLS, hostnameOf, portOf,
};

// ------------------------------------------------------------------ CLI
if (require.main === module) {
  const [cmd, ...rest] = process.argv.slice(2);
  const getFlag = (name) => {
    const i = rest.indexOf(name);
    return i >= 0 && i + 1 < rest.length ? rest[i + 1] : null;
  };
  const db = open();
  try {
    if (cmd === 'ingest') {
      const tool = rest[0];
      const file = rest[1];
      if (!tool || !file) { console.error('usage: target-model.js ingest <tool> <file> [--target <host>]'); process.exit(2); }
      const raw = fs.readFileSync(file, 'utf8');
      const res = ingest(db, tool, raw, { target: getFlag('--target') });
      console.log(JSON.stringify(res));
      process.exit(res.ok ? 0 : 1);
    } else if (cmd === 'snapshot') {
      console.log(JSON.stringify(snapshot(db), null, 2));
    } else if (cmd === 'hosts') {
      const rows = [];
      for (const t of state.listTargets(db)) for (const h of state.listHosts(db, t.id)) rows.push({ target: t.host, ...h, ports: state.listPorts(db, h.id).length });
      console.log(JSON.stringify(rows, null, 2));
    } else if (cmd === 'services') {
      const rows = [];
      for (const t of state.listTargets(db)) for (const h of state.listHosts(db, t.id)) for (const p of state.listPorts(db, h.id)) if (p.service) rows.push({ host: h.address, port: p.port, protocol: p.protocol, service: p.service, version: p.version });
      console.log(JSON.stringify(rows, null, 2));
    } else if (cmd === 'vulns') {
      console.log(JSON.stringify(listVulns(db), null, 2));
    } else if (cmd === 'creds') {
      console.log(JSON.stringify(listCreds(db).map((c) => ({ ...c, secret: '***' })), null, 2));
    } else if (cmd === 'tech') {
      console.log(JSON.stringify(listTechnologies(db), null, 2));
    } else if (cmd === 'accounts') {
      console.log(JSON.stringify(listAccounts(db), null, 2));
    } else if (cmd === 'shares') {
      console.log(JSON.stringify(listShares(db), null, 2));
    } else if (cmd === 'entities') {
      console.log(JSON.stringify(toEntities(db), null, 2));
    } else {
      console.error('usage: target-model.js <ingest|snapshot|hosts|services|vulns|creds|entities>');
      process.exit(2);
    }
  } finally {
    if (db && typeof db.close === 'function') db.close();
  }
}
