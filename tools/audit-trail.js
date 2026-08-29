#!/usr/bin/env node
// C5w (Ondata 4) — audit trail ISOLATO append-only write-once per invocazione wrapper.
//   artifacts/audit/<YYYY-MM-DD>.jsonl   (env AUDIT_DIR per i test, MAI path reali)
// Ogni riga = UNA invocazione di tools/run.js con hash-chain LEGGERA (sha256 della riga
// precedente, genesis '0'*64) — coerente con la hash-chain A3 dei findings (record-finding).
//
// Garanzie:
//   - APPEND-ONLY: il modulo espone SOLO append/verify/show. NESSUNA primitiva delete/rename:
//     i subagent non hanno alcun tool che possa modificare/eliminare righe su questa directory
//     (i tool dell'harness non espongono rm/mv su artifacts/audit); la chain rende comunque
//     visibile QUALSIASI manomissione (verify).
//   - Permessi restrittivi: directory 0o700, file 0o600.
//   - Scrittura ATOMICA tmp+rename senza residui.
//   - Fail-closed: append su chain rotta viene RIFIUTATA (mai accodare su un trail manomesso).
//
// CLI:
//   node tools/audit-trail.js append '<entry-json>'   # una riga (con chain) sul file odierno
//   node tools/audit-trail.js verify [file]           # verifica la chain (exit 0/1)
//   node tools/audit-trail.js show [file] [--tail N]  # lettura (read-only)
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const GENESIS = '0'.repeat(64);
const DEFAULT_DIR = path.join(__dirname, '..', 'artifacts', 'audit');

function auditDir() {
  return process.env.AUDIT_DIR || DEFAULT_DIR;
}

function auditFile(ts) {
  const d = ts ? new Date(ts) : new Date();
  const day = d.toISOString().slice(0, 10);
  return path.join(auditDir(), `${day}.jsonl`);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// Verify a raw (non-empty) line array of the trail. Same semantics as A3:
//   { ok:true, chained } | { ok:false, index, reason }
function verifyAuditChain(lines) {
  let chained = 0;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    let o = null;
    try { o = JSON.parse(raw); } catch { /* chain hash is raw-text based */ }
    if (!o || typeof o.chain !== 'object' || o.chain === null) {
      return { ok: false, index: i, reason: `line ${i + 1} has no chain entry (trail must be uniformly chained from genesis)` };
    }
    const expectedPrev = i === 0 ? GENESIS : sha256Hex(lines[i - 1]);
    if (o.chain.prev_sha256 !== expectedPrev)
      return { ok: false, index: i, reason: `prev_sha256 mismatch at line ${i + 1} (expected ${expectedPrev.slice(0, 12)}…)` };
    if (o.chain.seq !== i + 1)
      return { ok: false, index: i, reason: `seq gap at line ${i + 1}: chain.seq=${o.chain.seq}, expected ${i + 1}` };
    chained++;
  }
  return { ok: true, chained };
}

function readLines(file) {
  try { return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean); } catch { return []; }
}

function append(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry))
    return { ok: false, error: 'entry must be an object' };
  let line;
  try { line = JSON.stringify(entry); } catch (e) { return { ok: false, error: 'entry not serializable: ' + e.message }; }
  const file = auditFile(entry.ts);
  try {
    fs.mkdirSync(auditDir(), { recursive: true, mode: 0o700 });
    fs.chmodSync(auditDir(), 0o700);
  } catch (e) { return { ok: false, error: 'cannot create audit dir: ' + e.message }; }
  const existing = readLines(file);
  const chainState = verifyAuditChain(existing);
  if (!chainState.ok)
    return { ok: false, error: `audit trail chain BROKEN (${file}): ${chainState.reason} — refusing to append (fail-closed)` };
  const chained = {
    ...entry,
    chain: {
      seq: existing.length + 1,
      prev_sha256: existing.length ? sha256Hex(existing[existing.length - 1]) : GENESIS,
      ts: entry.ts || new Date().toISOString(),
    },
  };
  const raw = JSON.stringify(chained);
  // Append-only atomico: riscrive tmp+rename (nessun residuo), permessi 0o600.
  const tmp = file + '.' + process.pid + '.tmp';
  try {
    fs.writeFileSync(tmp, existing.length ? existing.join('\n') + '\n' + raw + '\n' : raw + '\n', { mode: 0o600 });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch {}
    return { ok: false, error: 'append failed: ' + e.message };
  }
  const selfCheck = verifyAuditChain(readLines(file));
  if (!selfCheck.ok) return { ok: false, error: 'post-append self-check failed: ' + selfCheck.reason };
  return { ok: true, file, seq: chained.chain.seq, prev_sha256: chained.chain.prev_sha256 };
}

function verifyAuditFile(file) {
  file = file || auditFile();
  const lines = readLines(file);
  if (!lines.length) return { ok: true, file, chained: 0, detail: 'audit trail empty/absent' };
  const r = verifyAuditChain(lines);
  return { ok: r.ok, file, chained: r.chained, index: r.index || null, reason: r.reason || null };
}

// --- CLI ---------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (cmd === 'append') {
    let e;
    try { e = JSON.parse(args[1] || ''); } catch (err) {
      console.log(JSON.stringify({ ok: false, error: 'invalid entry JSON: ' + err.message }));
      return 1;
    }
    const r = append(e);
    console.log(JSON.stringify(r));
    return r.ok ? 0 : 1;
  }
  if (cmd === 'verify') {
    const r = verifyAuditFile(args[1]);
    console.log(JSON.stringify(r));
    return r.ok ? 0 : 1;
  }
  if (cmd === 'show') {
    const file = args[1] || auditFile();
    const tailIdx = args.indexOf('--tail');
    const tail = tailIdx >= 0 ? Math.max(1, parseInt(args[tailIdx + 1], 10) || 20) : null;
    const lines = readLines(file);
    const out = tail ? lines.slice(-tail) : lines;
    for (const l of out) console.log(l);
    return 0;
  }
  console.error('usage: node tools/audit-trail.js append \'<entry-json>\' | verify [file] | show [file] [--tail N]');
  console.error('       env: AUDIT_DIR (default <ws>/artifacts/audit)');
  return 2;
}

if (require.main === module) process.exit(main());

module.exports = { auditDir, auditFile, append, verifyAuditChain, verifyAuditFile, sha256Hex, GENESIS, readLines };
