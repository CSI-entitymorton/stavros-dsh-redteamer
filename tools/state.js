#!/usr/bin/env node
// Structured recon/enumeration state for the Kali pipeline (Fase 1+). SQLite via node:sqlite
// (built into Node >= 22.5 — no npm deps, keeps the harness zero-dependency) while giving real
// querying, dedup and resume. Findings stay in reports/findings.jsonl (record-finding.js) and
// C2 sessions in reports/sessions.json (sessions.js): this DB holds ONLY targets/hosts/ports/
// endpoints/runs. Env override STATE_DB for tests.
const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

const DB_PATH = () => process.env.STATE_DB || path.join(__dirname, '..', 'reports', 'state.db');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  command TEXT,
  target TEXT,
  status TEXT NOT NULL DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS phases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  started_at TEXT,
  finished_at TEXT,
  UNIQUE(run_id, name)
);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL UNIQUE,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  address TEXT NOT NULL,
  hostname TEXT,
  alive INTEGER NOT NULL DEFAULT 1,
  os TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(target_id, address)
);
CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL REFERENCES hosts(id),
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  service TEXT,
  version TEXT,
  state TEXT NOT NULL DEFAULT 'open',
  UNIQUE(host_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  method TEXT NOT NULL DEFAULT 'GET',
  url TEXT NOT NULL,
  params TEXT,
  auth INTEGER NOT NULL DEFAULT 0,
  tech TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(target_id, method, url)
);
`;

const now = () => new Date().toISOString();

function open(file) {
  const p = file || DB_PATH();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const db = new DatabaseSync(p);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec(SCHEMA);
  return db;
}

// ---- runs (pipeline bookkeeping / resume) ----
// `target` is the assessed host/CIDR the run belongs to; it's what `resume` uses to
// re-drive incomplete phases. `command` stays the human-readable invocation.
function addRun(db, command, target) {
  const info = db.prepare('INSERT INTO runs (started_at, command, target, status) VALUES (?, ?, ?, ?)')
    .run(now(), command || null, target || null, 'running');
  return Number(info.lastInsertRowid);
}
function finishRun(db, id, status) {
  db.prepare('UPDATE runs SET finished_at = ?, status = ? WHERE id = ?').run(now(), status, id);
}
function lastRun(db) {
  return db.prepare('SELECT * FROM runs ORDER BY id DESC LIMIT 1').get() || null;
}

// ---- phases (per-run progress; pending -> running -> done/failed) ----
function setPhase(db, runId, name, status) {
  const ts = now();
  const started = status === 'running' ? ts : null;
  const finished = status === 'done' || status === 'failed' ? ts : null;
  db.prepare(
    'INSERT INTO phases (run_id, name, status, started_at, finished_at) VALUES (?, ?, ?, ?, ?) ' +
    'ON CONFLICT(run_id, name) DO UPDATE SET status = excluded.status, ' +
    'started_at = COALESCE(excluded.started_at, phases.started_at), finished_at = excluded.finished_at'
  ).run(runId, name, status, started, finished);
}
function getPhase(db, runId, name) {
  return db.prepare('SELECT * FROM phases WHERE run_id = ? AND name = ?').get(runId, name) || null;
}
function listPhases(db, runId) {
  return db.prepare('SELECT * FROM phases WHERE run_id = ? ORDER BY name').all(runId);
}

// ---- targets (the authorized host the run is assessing) ----
function upsertTarget(db, host) {
  const ts = now();
  db.prepare('INSERT INTO targets (host, first_seen, last_seen) VALUES (?, ?, ?) ON CONFLICT(host) DO UPDATE SET last_seen = excluded.last_seen')
    .run(host, ts, ts);
  return Number(db.prepare('SELECT id FROM targets WHERE host = ?').get(host).id);
}
function getTarget(db, host) {
  return db.prepare('SELECT * FROM targets WHERE host = ?').get(host) || null;
}
function listTargets(db) {
  return db.prepare('SELECT * FROM targets ORDER BY host').all();
}

// ---- live hosts / IPs discovered per target ----
function upsertHost(db, targetId, address, extra) {
  const ts = now();
  const e = extra || {};
  db.prepare(
    'INSERT INTO hosts (target_id, address, hostname, alive, os, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(target_id, address) DO UPDATE SET hostname = COALESCE(excluded.hostname, hosts.hostname), ' +
    'alive = excluded.alive, os = COALESCE(excluded.os, hosts.os), last_seen = excluded.last_seen'
  ).run(targetId, address, e.hostname || null, e.alive == null ? 1 : e.alive, e.os || null, ts, ts);
  return Number(db.prepare('SELECT id FROM hosts WHERE target_id = ? AND address = ?').get(targetId, address).id);
}
function listHosts(db, targetId) {
  return db.prepare('SELECT * FROM hosts WHERE target_id = ? ORDER BY address').all(targetId);
}

// ---- open ports / services per host ----
function upsertPort(db, hostId, port, protocol, service, version, state) {
  db.prepare(
    'INSERT INTO ports (host_id, port, protocol, service, version, state) VALUES (?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(host_id, port, protocol) DO UPDATE SET service = COALESCE(excluded.service, ports.service), ' +
    'version = COALESCE(excluded.version, ports.version), state = excluded.state'
  ).run(hostId, port, protocol || 'tcp', service || null, version || null, state || 'open');
}
function listPorts(db, hostId) {
  return db.prepare('SELECT * FROM ports WHERE host_id = ? ORDER BY port').all(hostId);
}

// ---- web endpoints / params discovered per target ----
function upsertEndpoint(db, targetId, method, url, extra) {
  const ts = now();
  const e = extra || {};
  db.prepare(
    'INSERT INTO endpoints (target_id, method, url, params, auth, tech, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(target_id, method, url) DO UPDATE SET params = COALESCE(excluded.params, endpoints.params), ' +
    'auth = excluded.auth, tech = COALESCE(excluded.tech, endpoints.tech), last_seen = excluded.last_seen'
  ).run(targetId, String(method || 'GET').toUpperCase(), url, e.params != null ? JSON.stringify(e.params) : null, e.auth ? 1 : 0, e.tech || null, ts, ts);
}
function listEndpoints(db, targetId) {
  return db.prepare('SELECT * FROM endpoints WHERE target_id = ? ORDER BY url').all(targetId);
}

module.exports = {
  open, DB_PATH,
  addRun, finishRun, lastRun,
  setPhase, getPhase, listPhases,
  upsertTarget, getTarget, listTargets,
  upsertHost, listHosts,
  upsertPort, listPorts,
  upsertEndpoint, listEndpoints,
};
