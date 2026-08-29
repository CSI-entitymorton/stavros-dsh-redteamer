#!/usr/bin/env node
// E13 (rimandati) — continuation-advice per i goal round: consiglio DETERMINISTICO derivato
// dalle ultime N message/errori dei round di continuazione. Zero rete, zero LLM implicito:
// riusa la error-taxonomy di run.js per le recovery action e rileva pattern (loop, tutto
// fallito) SENZA eseguire alcuna azione.
//
// Input (jsonl, --log): righe eterogenee — audit run.js ({ts,bin,blocked,error_class,reason,
// exit}), workflow step log ({event:'step'|'run_summary', exit, step}), o messaggi generici
// ({role, text|content|error}). Ogni riga viene normalizzata e classificata.
//
// CLI:
//   node tools/continuation.js advise --log <file> --tail N [--json]
'use strict';
const fs = require('fs');
const runLib = require('./run'); // ERROR_TAXONOMY + classifyFailure

function readLines(file) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}

// Normalizza una riga → {ts, kind: ok|error|blocked|message, text, error_class}.
function normalize(line) {
  const text = String(line.text || line.content || line.message || line.reason || line.error || line.stdout_tail || line.stderr_tail || '');
  if (line.event === 'run_summary') return { ts: line.ts, kind: line.ok ? 'ok' : 'error', text: 'run_summary ok=' + line.ok, error_class: null };
  if (line.event === 'step') {
    const failed = line.exit != null && line.exit !== 0;
    return { ts: line.ts, kind: failed ? 'error' : 'ok', text: `step ${line.step} exit=${line.exit}`, error_class: failed ? 'unknown' : null };
  }
  if (line.blocked) return { ts: line.ts, kind: 'blocked', text: (line.reason || '') + ' ' + text, error_class: line.error_class || 'scope_blocked' };
  if (line.error_class) return { ts: line.ts, kind: 'error', text, error_class: line.error_class };
  if (line.exit != null && line.exit !== 0) return { ts: line.ts, kind: 'error', text, error_class: runLib.classifyFailure({ exitCode: line.exit, text }) || 'unknown' };
  if (line.error) return { ts: line.ts, kind: 'error', text, error_class: runLib.classifyFailure({ text }) || 'unknown' };
  return { ts: line.ts, kind: 'message', text, error_class: null };
}

/**
 * Consiglio per i round di continuazione. opts: {logFile, tail}
 * Ritorna { ok, advice:[{action,hint,from}], analysis:{recent, error_classes, all_failed, loop} }.
 */
function advise(opts) {
  opts = opts || {};
  const lines = readLines(opts.logFile);
  const tail = Math.max(1, opts.tail || 8);
  const recent = lines.slice(-tail).map(normalize);
  const advice = [];

  const errorClasses = [...new Set(recent.filter((r) => r.error_class).map((r) => r.error_class))];
  const allFailed = recent.length > 0 && recent.every((r) => r.kind === 'error' || r.kind === 'blocked');
  // Loop: stessa coppia (kind+text) ripetuta ≥ 3 volte nelle ultime N.
  const counts = {};
  for (const r of recent) {
    const k = `${r.kind}|${r.text.slice(0, 60)}`;
    counts[k] = (counts[k] || 0) + 1;
  }
  const loopKey = Object.keys(counts).find((k) => counts[k] >= 3);

  for (const cls of errorClasses) {
    const t = runLib.ERROR_TAXONOMY[cls];
    if (t) advice.push({ action: t.recovery, hint: t.hint, from: `error_class ${cls}` });
  }
  if (loopKey) {
    advice.push({ action: 'break_loop', hint: `pattern ripetuto ${counts[loopKey]} volte (${loopKey.split('|')[1].slice(0, 60)}): ferma e cambia approccio (vedi tools/loop-watch.js / tools/recover.js)`, from: 'continuation.js' });
  }
  if (allFailed) {
    advice.push({ action: 'recover_from_artifacts', hint: 'ultime ' + recent.length + ' voci tutte in errore: NON ripetere; ricostruisci dagli artefatti (node tools/recover.js plan) e riparti dal prossimo step valido', from: 'continuation.js' });
  }
  if (!advice.length) {
    const last = recent[recent.length - 1];
    advice.push({ action: 'continue', hint: last ? `nessun errore nelle ultime ${recent.length} voci (ultima: ${last.kind}) — continua il goal` : 'nessun log: inizia il primo round', from: 'continuation.js' });
  }

  return {
    ok: true,
    analysis: {
      recent: recent.map((r) => ({ ts: r.ts, kind: r.kind, error_class: r.error_class, text: r.text.slice(0, 120) })),
      error_classes: errorClasses,
      all_failed: allFailed,
      loop: !!loopKey,
    },
    advice,
  };
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (cmd !== 'advise') {
    console.error('usage: node tools/continuation.js advise --log <file> --tail N [--json]');
    process.exit(2);
  }
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
  const log = opt('--log');
  if (!log) { console.error('advise richiede --log <file>'); process.exit(2); }
  const r = advise({ logFile: log, tail: parseInt(opt('--tail'), 10) || undefined });
  console.log(JSON.stringify(r, null, argv.includes('--json') ? 2 : 0));
  process.exit(r.advice.some((a) => a.action === 'break_loop' || a.action === 'recover_from_artifacts') ? 1 : 0);
}

if (require.main === module) process.exit(main());
module.exports = { advise, normalize, readLines };
