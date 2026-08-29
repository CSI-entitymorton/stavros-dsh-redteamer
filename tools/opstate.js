#!/usr/bin/env node
// C2w (Ondata 3) — operation-state.json revisionato: transizioni APPEND-ONLY, lease per
// sub-agent concorrenti, rifiuto di scrivere su revisione stantia (compare-and-swap sul
// campo `revision`). Pattern da PentestGPT P4 (§3.2 del documento migliorie).
//
// INTEGRAZIONE CON BUDGET (vincolo di handoff: "INTEGRA, non spezzare"):
//   tools/budget.js scrive GIÀ `.budget` in operation-state.json tramite loadStateOrCreate /
//   saveState / atomicWriteJson (write atomico tmp+rename, snapshot operation-state.snapshot-*.json).
//   Questo modulo RIUSA gli stessi helper (richiede ./budget) e lo stesso schema/atomicità:
//   nessuna duplicazione di IO, nessun formato parallelo. budget.js continua a funzionare
//   identico a prima: le sue scritture preservano i campi opstate (revision/transitions/leases)
//   e NON toccano il campo revision (writer esterno = scrittura opaca, semantica documentata);
//   le scritture opstate invece validano la revisione letta (CAS) prima di ogni save.
//   Disciplina: un writer per momento; le lease servono proprio a garantirla tra sub-agent.
//
// Schema aggiunto (additivo, mai distruttivo):
//   revision:    <int>      incrementato a OGNI scrittura opstate riuscita
//   transitions: [{seq, ts, owner, action, detail}]  APPEND-ONLY (mai riscritte/riordinate)
//   leases:      {<resource>: {owner, acquired_at, expires_at}}   scadenza pigra (lazy)
//
// CLI:
//   node tools/opstate.js show [--json]
//   node tools/opstate.js history [--tail N]
//   node tools/opstate.js mutate --owner <nome> --action <nome> [--detail '{"json":true}'] [--expect-revision N]
//   node tools/opstate.js lease acquire --resource R --owner X --ttl <sec> [--expect-revision N]
//   node tools/opstate.js lease renew  --resource R --owner X --ttl <sec> [--expect-revision N]
//   node tools/opstate.js lease release --resource R --owner X [--expect-revision N]
//   node tools/opstate.js accounting [--audit <run-audit.jsonl>] [--record <label> --owner X] [--expect-revision N]
//     C4w/F8 (Ondata 4): aggregati token/costo per SESSIONE (totals + per-action + per-agent)
//     dal run-audit (env RUN_AUDIT_FILE). Senza --record: sola lettura (zero scritture).
//     Con --record: UNA transizione append-only con i totali di sessione nel detail.
//
// Exit code: 0 ok · 2 uso errato · 3 revisione stantia (CAS conflict: ricaricare e riprovare)
//           · 4 lease in conflitto (risorsa trattenuta da altro owner non scaduto)
'use strict';
const fs = require('fs');
const path = require('path');
const budget = require('./budget'); // riuso: loadStateOrCreate / saveState / atomicWriteJson

const ROOT = path.join(__dirname, '..');

function resolveStateFile(cli) {
  return cli.state || process.env.OPSTATE_FILE || process.env.BUDGET_STATE_FILE ||
    path.join(ROOT, 'operation-state.json');
}

function nowIso() { return new Date().toISOString(); }

// Identical to budget.js saveState() (not exported there) — built on its exported
// atomicWriteJson so IO semantics (tmp+rename, JSON shape) stay byte-compatible.
function saveState(st, file) {
  st.updated_at = nowIso();
  budget.atomicWriteJson(file, st);
}

/** Load state ensuring the opstate fields exist (never destroying budget/pending data). */
function loadOpState(file) {
  const st = budget.loadStateOrCreate(file); // same creation shape as budget.js
  if (!st.budget || typeof st.budget !== 'object') st.budget = {};
  if (typeof st.revision !== 'number') st.revision = 0;
  if (!Array.isArray(st.transitions)) st.transitions = [];
  if (!st.leases || typeof st.leases !== 'object') st.leases = {};
  return st;
}

/**
 * Compare-and-swap update. Reads FRESH state, requires current revision === expectRevision,
 * applies mutator (a throw aborts WITHOUT writing), bumps revision and appends ONE
 * transition. Returns {ok:true, revision, seq} or {ok:false, stale:true, expected, current}.
 */
function casUpdate(file, expectRevision, mutator, meta) {
  meta = meta || {};
  const owner = String(meta.owner || 'unknown').slice(0, 80);
  const action = String(meta.action || 'mutate').slice(0, 80);
  const st = loadOpState(file);
  const current = typeof st.revision === 'number' ? st.revision : 0;
  const expected = typeof expectRevision === 'number' ? expectRevision : current;
  if (expected !== current) {
    return { ok: false, stale: true, expected, current,
      note: 'revisione stantia: ricarica lo stato (show) e riapplica sul valore corrente' };
  }
  // mutator works on the loaded object; a throw here leaves the file untouched.
  mutator(st);
  st.revision = current + 1;
  st.transitions.push({
    seq: st.transitions.length + 1,
    ts: nowIso(),
    owner,
    action,
    detail: meta.detail === undefined ? null : meta.detail,
  });
  saveState(st, file); // stessa semantica di budget.js (tmp+rename via atomicWriteJson)
  return { ok: true, revision: st.revision, seq: st.transitions.length };
}

// ---- leases -----------------------------------------------------------------

function leaseView(st, resource) {
  const l = st.leases[resource];
  if (!l) return null;
  const expired = Date.parse(l.expires_at) <= Date.now();
  return { ...l, resource, expired };
}

class LeaseConflict extends Error {
  constructor(payload) { super('lease-conflict'); this.payload = payload; }
}

/** Run casUpdate translating an internal LeaseConflict into a structured rejection. */
function casLease(file, expectRevision, mutator, meta) {
  let conflict = null;
  let res;
  try {
    res = casUpdate(file, expectRevision, mutator, meta);
  } catch (e) {
    if (e instanceof LeaseConflict) { conflict = e.payload; res = { ok: false, stale: false }; }
    else throw e;
  }
  return { res, conflict };
}

function leaseAcquire(file, { resource, owner, ttlSec, expectRevision }) {
  if (!resource || !owner || !(ttlSec > 0)) return { ok: false, usage: true };
  const { res, conflict } = casLease(file, expectRevision, (st) => {
    const cur = leaseView(st, resource);
    if (cur && !cur.expired && cur.owner !== owner) {
      throw new LeaseConflict({ holder: cur.owner, expires_at: cur.expires_at });
    }
    st.leases[resource] = { owner, acquired_at: nowIso(), expires_at: new Date(Date.now() + ttlSec * 1000).toISOString() };
  }, { owner, action: 'lease-acquire', detail: { resource, ttl_sec: ttlSec } });
  if (conflict) return { ok: false, conflict };
  return res;
}

function leaseRenew(file, { resource, owner, ttlSec, expectRevision }) {
  if (!resource || !owner || !(ttlSec > 0)) return { ok: false, usage: true };
  const { res, conflict } = casLease(file, expectRevision, (st) => {
    const cur = leaseView(st, resource);
    if (!cur || cur.owner !== owner) throw new LeaseConflict({ holder: cur ? cur.owner : null });
    st.leases[resource].expires_at = new Date(Date.now() + ttlSec * 1000).toISOString();
  }, { owner, action: 'lease-renew', detail: { resource, ttl_sec: ttlSec } });
  if (conflict) return { ok: false, conflict };
  return res;
}

function leaseRelease(file, { resource, owner, expectRevision }) {
  if (!resource || !owner) return { ok: false, usage: true };
  const { res, conflict } = casLease(file, expectRevision, (st) => {
    const cur = leaseView(st, resource);
    if (cur && cur.owner !== owner && !cur.expired) throw new LeaseConflict({ holder: cur.owner });
    delete st.leases[resource]; // rimozione del LEASE, mai delle transizioni (append-only resta)
  }, { owner, action: 'lease-release', detail: { resource } });
  if (conflict) return { ok: false, conflict };
  return res;
}

// ---- CLI --------------------------------------------------------------------

function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--owner') o.owner = argv[++i];
    else if (a === '--action') o.action = argv[++i];
    else if (a === '--detail') o.detailRaw = argv[++i];
    else if (a === '--resource') o.resource = argv[++i];
    else if (a === '--ttl') o.ttl = parseInt(argv[++i], 10);
    else if (a === '--expect-revision') o.expectRevision = parseInt(argv[++i], 10);
    else if (a === '--tail') o.tail = Math.max(1, parseInt(argv[++i], 10) || 20);
    else if (a === '--state') o.state = argv[++i];
    else if (a === '--audit') o.audit = argv[++i];
    else if (a === '--record') o.record = argv[++i];
    else if (a === '--json') o.json = true;
    else o._.push(a);
  }
  return o;
}

function parseDetail(raw) {
  if (raw == null) return null;
  try {
    const v = JSON.parse(raw);
    if (v == null || typeof v !== 'object' || Array.isArray(v)) return v === null ? null : v;
    return v;
  } catch {
    console.error('uso errato: --detail deve essere JSON valido');
    process.exit(2);
  }
}

function failStale(res) {
  console.error(JSON.stringify({ ok: false, error: 'stale-revision', ...res }));
  process.exit(3);
}
function failLease(res) {
  console.error(JSON.stringify({ ok: false, error: 'lease-conflict', ...res }));
  process.exit(4);
}

function main() {
  const cli = parseArgs(process.argv.slice(2));
  const [cmd, sub] = cli._;
  const file = resolveStateFile(cli);

  if (cmd === 'show') {
    const st = loadOpState(file);
    const leases = {};
    for (const [r, l] of Object.entries(st.leases)) leases[r] = leaseView(st, r);
    const out = { state_file: file, revision: st.revision, transitions: st.transitions.length,
      leases, budget_present: !!st.budget && Object.keys(st.budget).length > 0,
      created_at: st.created_at, updated_at: st.updated_at };
    console.log(JSON.stringify(out, null, 2));
    return 0;
  }
  if (cmd === 'history') {
    const st = loadOpState(file);
    const rows = cli.tail ? st.transitions.slice(-cli.tail) : st.transitions;
    console.log(JSON.stringify({ revision: st.revision, total: st.transitions.length, rows }, null, 2));
    return 0;
  }
  if (cmd === 'accounting') {
    // C4w/F8 (Ondata 4): aggregati di sessione dal run-audit. Read-only senza --record;
    // con --record appende UNA transizione (append-only, mai riscritture) con i totali.
    const accounting = require('./accounting');
    const auditFile = cli.audit || process.env.RUN_AUDIT_FILE || path.join(ROOT, 'reports', 'tmp', 'run-audit.jsonl');
    const agg = accounting.aggregateAll(accounting.loadAuditLines(auditFile));
    if (cli.record) {
      if (!cli.owner) {
        console.error('uso errato: accounting --record richiede --owner');
        process.exit(2);
      }
      const res = casUpdate(file, cli.expectRevision, () => {}, {
        owner: cli.owner, action: `accounting:${cli.record}`, detail: { source: auditFile, ...agg.session },
      });
      if (!res.ok) return failStale(res);
      console.log(JSON.stringify({ ok: true, recorded: true, transition_seq: res.seq, accounting: agg.session }, null, 2));
      return 0;
    }
    console.log(JSON.stringify({ ok: true, source: auditFile, accounting: agg }, null, 2));
    return 0;
  }
  if (cmd === 'mutate') {
    if (!cli.owner || !cli.action) {
      console.error('uso errato: mutate richiede --owner e --action');
      process.exit(2);
    }
    const detail = parseDetail(cli.detailRaw);
    const res = casUpdate(file, cli.expectRevision, () => {}, { owner: cli.owner, action: cli.action, detail });
    if (!res.ok) return failStale(res);
    console.log(JSON.stringify({ ok: true, ...res }, null, 2));
    return 0;
  }
  if (cmd === 'lease') {
    if (sub === 'acquire' || sub === 'renew') {
      if (!cli.owner || !cli.resource || !(cli.ttl > 0)) {
        console.error('uso errato: lease acquire/renew richiedono --resource --owner --ttl <sec>');
        process.exit(2);
      }
      const res = sub === 'acquire'
        ? leaseAcquire(file, { resource: cli.resource, owner: cli.owner, ttlSec: cli.ttl, expectRevision: cli.expectRevision })
        : leaseRenew(file, { resource: cli.resource, owner: cli.owner, ttlSec: cli.ttl, expectRevision: cli.expectRevision });
      if (res.usage) { console.error('uso errato'); process.exit(2); }
      if (res.conflict) return failLease(res);
      if (!res.ok) return failStale(res);
      console.log(JSON.stringify({ ok: true, ...res }, null, 2));
      return 0;
    }
    if (sub === 'release') {
      if (!cli.owner || !cli.resource) {
        console.error('uso errato: lease release richiede --resource --owner');
        process.exit(2);
      }
      const res = leaseRelease(file, { resource: cli.resource, owner: cli.owner, expectRevision: cli.expectRevision });
      if (res.conflict) return failLease(res);
      if (!res.ok) return failStale(res);
      console.log(JSON.stringify({ ok: true, ...res }, null, 2));
      return 0;
    }
    console.error('uso errato: lease acquire|renew|release');
    process.exit(2);
  }
  console.error('usage: node tools/opstate.js show|history|accounting|mutate|lease <acquire|renew|release> [...]');
  console.error('       env: OPSTATE_FILE / BUDGET_STATE_FILE / --state <file> (default <ws>/operation-state.json)');
  process.exit(2);
}

if (require.main === module) process.exit(main());

module.exports = { resolveStateFile, loadOpState, casUpdate, leaseAcquire, leaseRenew, leaseRelease, parseArgs, LeaseConflict };
