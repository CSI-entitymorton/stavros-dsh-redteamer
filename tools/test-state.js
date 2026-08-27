// Offline self-check for the SQLite state layer (node:sqlite, zero-dep).
// Run: node tools/test-state.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const state = require('./state');

const dbFile = path.join(os.tmpdir(), 'state-' + process.pid + '.db');
const db = state.open(dbFile);

// --- runs (bookkeeping / resume) ---
const runId = state.addRun(db, 'recon example.com', 'example.com');
assert.ok(runId >= 1, 'run id assigned');
assert.strictEqual(state.lastRun(db).status, 'running');
assert.strictEqual(state.lastRun(db).target, 'example.com');
state.finishRun(db, runId, 'done');
assert.strictEqual(state.lastRun(db).status, 'done');

// --- phases (per-run progress / resume) ---
const runId2 = state.addRun(db, 'scan example.com', 'example.com');
assert.strictEqual(state.getPhase(db, runId2, 'scan'), null, 'no phase yet');
state.setPhase(db, runId2, 'scan', 'running');
assert.strictEqual(state.getPhase(db, runId2, 'scan').status, 'running');
assert.ok(state.getPhase(db, runId2, 'scan').started_at, 'started_at set');
state.setPhase(db, runId2, 'scan', 'done');
assert.strictEqual(state.getPhase(db, runId2, 'scan').status, 'done');
assert.strictEqual(state.getPhase(db, runId2, 'scan').started_at != null, true, 'started_at preserved on done');
assert.ok(state.getPhase(db, runId2, 'scan').finished_at, 'finished_at set');
const phases = state.listPhases(db, runId2);
assert.strictEqual(phases.length, 1, 'one phase listed');
assert.strictEqual(phases[0].name, 'scan');

// --- targets: upsert dedup ---
const t1 = state.upsertTarget(db, 'example.com');
const t1b = state.upsertTarget(db, 'example.com');
assert.strictEqual(t1, t1b, 'target upsert dedups');
assert.strictEqual(state.getTarget(db, 'example.com').host, 'example.com');
assert.strictEqual(state.listTargets(db).length, 1);

// --- hosts + ports: upsert dedup, COALESCE keeps existing fields ---
const h1 = state.upsertHost(db, t1, '93.184.216.34', { hostname: 'example.com', os: 'linux' });
const h1b = state.upsertHost(db, t1, '93.184.216.34', { alive: 1 }); // null hostname/os must not clobber
assert.strictEqual(h1, h1b, 'host upsert dedups');
assert.strictEqual(state.listHosts(db, t1).length, 1);
assert.strictEqual(state.listHosts(db, t1)[0].hostname, 'example.com');

state.upsertPort(db, h1, 443, 'tcp', 'https', 'nginx', 'open');
state.upsertPort(db, h1, 443, 'tcp', 'https', 'nginx/1.25', 'open'); // merge keeps latest version
const ports = state.listPorts(db, h1);
assert.strictEqual(ports.length, 1, 'port dedup: ' + JSON.stringify(ports));
assert.strictEqual(ports[0].version, 'nginx/1.25');

// --- endpoints: upsert dedup, params merged ---
state.upsertEndpoint(db, t1, 'GET', 'https://example.com/api/x', { params: ['id'], auth: 1 });
state.upsertEndpoint(db, t1, 'GET', 'https://example.com/api/x', { params: ['id', 'q'], auth: 1 });
const eps = state.listEndpoints(db, t1);
assert.strictEqual(eps.length, 1, 'endpoint dedup');
assert.deepStrictEqual(JSON.parse(eps[0].params), ['id', 'q']);

// --- persistence across reopen (resume capability) ---
db.close();
const db2 = state.open(dbFile);
assert.strictEqual(state.listTargets(db2).length, 1, 'state persists across reopen');
db2.close();

// cleanup (main db + possible WAL sidecars)
for (const s of ['', '-wal', '-shm']) {
  try { fs.rmSync(dbFile + s, { force: true }); } catch {}
}
console.log('state: all tests passed');
