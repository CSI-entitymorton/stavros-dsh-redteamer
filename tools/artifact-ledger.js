#!/usr/bin/env node
// F5 (Ondata 3) — Ledger Action→Artifact macchina-leggibile: CHI ha prodotto QUALE artefatto,
// con timestamp + hash sha256, in un JSONL append-only coerente con evidence-index.md e
// reports/tmp/coverage-workflow.json (workflow.js incide qui le sue artifacts — hook additivo).
//
// Store: ARTIFACT_LEDGER_FILE env | --ledger <file> | reports/tmp/artifact-ledger.jsonl
//   una riga = un artefatto prodotto da un'azione:
//   { seq, ts, action_id, producer, kind, artifact, sha256, bytes, exit?, params?, note? }
//
// Comandi:
//   node tools/artifact-ledger.js record --action <id> --artifact <path> [--artifact p2 ...]
//        [--producer <chi>] [--kind <tipo>] [--exit N] [--params '{"json":...}'] [--note s]
//   node tools/artifact-ledger.js verify            # ri-hasha TUTTO: missing/mismatch → exit≠0
//   node tools/artifact-ledger.js show [--action a] [--producer p] [--limit N] [--json]
//   node tools/artifact-ledger.js evidence --evidence-index <file> [--action a]
//        # appende righe E- single-writer (stessa convenzione di workflow/poc-replay/listen-audit)
//
// Garanzie: solo artefatti REALI ed esistenti entrano nel ledger (come per evidence-index:
// dichiarato ma mai prodotto = non registrato); verify rende il ledger anti-false-positive
// (un artefatto cancellato/manomesso viene segnalato). Append-only: nessuna riscrittura.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const WS_ROOT = path.join(__dirname, '..');

function resolveLedgerFile(cli) {
  return cli.ledger || process.env.ARTIFACT_LEDGER_FILE || path.join(WS_ROOT, 'reports', 'tmp', 'artifact-ledger.jsonl');
}

function readEntries(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

function nextSeq(entries) {
  return entries.reduce((m, e) => Math.max(m, Number(e.seq) || 0), 0) + 1;
}

function sha256File(p) {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

/** Record ONE artifact for an action (library entry point; used by workflow.js too). */
function recordEntry(ledgerFile, entry) {
  const st = entry.artifactStat;
  delete entry.artifactStat;
  const line = JSON.stringify(entry);
  fs.mkdirSync(path.dirname(ledgerFile), { recursive: true });
  fs.appendFileSync(ledgerFile, line + '\n');
  return entry;
}

function buildEntry(file, cli, artifactPath) {
  const abs = path.resolve(artifactPath);
  let stat;
  try { stat = fs.statSync(abs); } catch {
    throw new Error(`artefatto inesistente (non registrato): ${artifactPath}`);
  }
  if (!stat.isFile()) throw new Error(`non è un file regolare: ${artifactPath}`);
  const entries = readEntries(file);
  return {
    seq: nextSeq(entries),
    ts: new Date().toISOString(),
    action_id: String(cli.action || 'unnamed-action').slice(0, 120),
    producer: String(cli.producer || 'operator').slice(0, 80),
    kind: String(cli.kind || 'artifact').slice(0, 40),
    artifact: artifactPath,
    sha256: sha256File(abs),
    bytes: stat.size,
    exit: cli.exit != null ? cli.exit : undefined,
    params: cli.params != null ? cli.params : undefined,
    note: cli.note != null ? String(cli.note).slice(0, 300) : undefined,
  };
}

function verifyLedger(file) {
  const entries = readEntries(file);
  const missing = [];
  const mismatched = [];
  let okCount = 0;
  for (const e of entries) {
    let stat = null;
    try { stat = fs.statSync(path.resolve(e.artifact)); } catch {}
    if (!stat || !stat.isFile()) { missing.push({ seq: e.seq, artifact: e.artifact }); continue; }
    const h = sha256File(path.resolve(e.artifact));
    if (h !== e.sha256) mismatched.push({ seq: e.seq, artifact: e.artifact, expected: e.sha256, actual: h });
    else okCount++;
  }
  return { total: entries.length, ok: okCount, missing, hash_mismatch: mismatched,
    verdict: missing.length === 0 && mismatched.length === 0 ? 'intact' : 'compromised' };
}

function filterEntries(entries, { action, producer, limit } = {}) {
  let rows = entries;
  if (action) rows = rows.filter((e) => e.action_id === action);
  if (producer) rows = rows.filter((e) => e.producer === producer);
  if (limit) rows = rows.slice(-limit);
  return rows;
}

function appendEvidenceRows(eiFile, entries) {
  fs.mkdirSync(path.dirname(eiFile), { recursive: true });
  let n = 1;
  try {
    for (const m of fs.readFileSync(eiFile, 'utf8').matchAll(/^\|\s*E-(\d+)\s*\|/gm)) n = Math.max(n, parseInt(m[1], 10) + 1);
  } catch {}
  const date = new Date().toISOString().slice(0, 10);
  const lines = [];
  // Una riga per AZIONE (artefatti aggregati), così l'indice resta leggibile.
  const byAction = new Map();
  for (const e of entries) {
    if (!byAction.has(e.action_id)) byAction.set(e.action_id, []);
    byAction.get(e.action_id).push(e);
  }
  for (const [actionId, arts] of byAction) {
    const brief = arts.map((a) => `${path.basename(a.artifact)}#${String(a.sha256).slice(0, 12)}`).join(', ');
    lines.push(`| E-${String(n++).padStart(3, '0')} | ${date} | \`${arts[0].artifact}\` | artifact-ledger azione \`${actionId}\` producer=${arts[0].producer} artefatti=[${brief}] (${arts.length}) | artifact-ledger |`);
  }
  fs.appendFileSync(eiFile, lines.join('\n') + '\n');
  return lines.length;
}

// ---- CLI --------------------------------------------------------------------

function parseArgs(argv) {
  const o = { _: [], artifacts: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--action') o.action = argv[++i];
    else if (a === '--artifact') o.artifacts.push(argv[++i]);
    else if (a === '--producer') o.producer = argv[++i];
    else if (a === '--kind') o.kind = argv[++i];
    else if (a === '--exit') o.exit = parseInt(argv[++i], 10);
    else if (a === '--params') { try { o.params = JSON.parse(argv[++i]); } catch { console.error('--params deve essere JSON valido'); process.exit(2); } }
    else if (a === '--note') o.note = argv[++i];
    else if (a === '--ledger') o.ledger = argv[++i];
    else if (a === '--evidence-index') o.evidenceIndex = argv[++i];
    else if (a === '--limit') o.limit = parseInt(argv[++i], 10);
    else if (a === '--json') o.json = true;
    else o._.push(a);
  }
  return o;
}

function main() {
  const cli = parseArgs(process.argv.slice(2));
  const [cmd] = cli._;
  const file = resolveLedgerFile(cli);

  if (cmd === 'record') {
    if (!cli.action || !cli.artifacts.length) {
      console.error('uso errato: record richiede --action e almeno un --artifact');
      process.exit(2);
    }
    const recorded = [];
    for (const art of cli.artifacts) {
      try {
        recorded.push(recordEntry(file, buildEntry(file, cli, art)));
      } catch (e) {
        console.error(JSON.stringify({ ok: false, error: e.message }));
        process.exit(1);
      }
    }
    console.log(JSON.stringify({ ok: true, ledger: file, recorded: recorded.map((r) => ({ seq: r.seq, artifact: r.artifact, sha256: r.sha256 })) }, null, 2));
    return 0;
  }
  if (cmd === 'verify') {
    const res = verifyLedger(file);
    console.log(JSON.stringify({ ledger: file, ...res }, null, 2));
    process.exit(res.verdict === 'intact' ? 0 : 1);
  }
  if (cmd === 'show') {
    const rows = filterEntries(readEntries(file), cli);
    console.log(JSON.stringify({ ledger: file, count: rows.length, entries: rows }, null, 2));
    return 0;
  }
  if (cmd === 'evidence') {
    if (!cli.evidenceIndex) { console.error('uso errato: evidence richiede --evidence-index <file>'); process.exit(2); }
    const rows = filterEntries(readEntries(file), cli);
    if (!rows.length) { console.log(JSON.stringify({ ok: true, appended: 0, note: 'nessuna entry da registrare' })); return 0; }
    const appended = appendEvidenceRows(cli.evidenceIndex, rows);
    console.log(JSON.stringify({ ok: true, appended }, null, 2));
    return 0;
  }
  console.error('usage: node tools/artifact-ledger.js record|verify|show|evidence [...]');
  process.exit(2);
}

if (require.main === module) process.exit(main());

module.exports = { resolveLedgerFile, readEntries, buildEntry, recordEntry, verifyLedger, filterEntries, appendEvidenceRows };
