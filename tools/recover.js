#!/usr/bin/env node
// E8 (rimandati) — kind RECOVER formale: recovery dei "turni morti" ricostruendo dagli
// artefatti SENZA rigiocare le azioni (coerente con reflector/loop-watch già esistenti).
//
// Ricostruzione deterministica (stdlib, zero rete) da:
//   --audit <run-audit.jsonl>   (default reports/tmp/run-audit.jsonl o RUN_AUDIT_FILE)
//   --logdir <workflow logs>    (default reports/tmp/workflow — jsonl per-step)
//   --state <opstate.json>      (default operation-state.json o OPSTATE_FILE)
//   --findings <findings.jsonl> (default reports/findings.jsonl o FINDINGS_JSONL)
//
// Output: timeline delle invocazioni, ultimo stato (opstate), analisi del "turno morto"
// (ultime N invocazioni bloccate/fallite senza progresso) e CONSIGLIO DETERMINISTICO che
// riusa la error-taxonomy di run.js (recovery action per classe di errore). NIENTE replay:
// questo tool non esegue mai azioni — produce solo piano di ripresa.
//
// CLI:
//   node tools/recover.js plan [--audit <f>] [--logdir <d>] [--state <f>] [--findings <f>] [--tail N] [--json]
'use strict';
const fs = require('fs');
const path = require('path');
const runLib = require('./run'); // ERROR_TAXONOMY + classifyFailure riusati per l'advice

const WS = path.join(__dirname, '..');

function resolveFile(flagVal, envVar, def) {
  return flagVal || (envVar && process.env[envVar]) || def;
}

function readJsonl(file) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}

function latestWorkflowLogs(logDir) {
  const out = [];
  try {
    for (const f of fs.readdirSync(logDir).filter((f) => f.endsWith('.jsonl'))) {
      const full = path.join(logDir, f);
      const lines = readJsonl(full);
      if (!lines.length) continue;
      const summary = lines.filter((l) => l.event === 'run_summary').pop();
      const steps = lines.filter((l) => l.event === 'step');
      const failed = steps.filter((s) => s.exit != null && s.exit !== 0);
      out.push({
        file: f,
        summary: summary || null,
        steps_total: steps.length,
        failed_steps: failed.map((s) => ({ id: s.step, exit: s.exit, cmd: (s.cmd || '').slice(0, 120) })),
      });
    }
  } catch {}
  return out.sort((a, b) => String(a.file).localeCompare(String(b.file)));
}

function readOpstate(file) {
  try {
    const st = JSON.parse(fs.readFileSync(file, 'utf8'));
    return {
      revision: typeof st.revision === 'number' ? st.revision : 0,
      transitions: Array.isArray(st.transitions) ? st.transitions : [],
      leases: st.leases || {},
    };
  } catch { return { revision: 0, transitions: [], leases: {} }; }
}

// Classificazione delle ultime N invocazioni: ogni voce → {error_class, recovery} usando la
// STESSA taxonomy di run.js (nessuna duplicazione di semantica).
function classifyEntries(lines) {
  return lines.map((e) => {
    const cls = e.error_class || (e.blocked ? 'scope_blocked' : null);
    const t = runLib.ERROR_TAXONOMY[cls];
    return {
      ts: e.ts, bin: e.bin, blocked: !!e.blocked, ok: !!e.ok, exit: e.exit,
      error_class: cls,
      recovery: t ? { action: t.recovery, hint: t.hint } : null,
      detail: e.reason || (e.exit != null && e.exit !== 0 ? 'exit ' + e.exit : null),
    };
  });
}

/**
 * Ricostruzione + analisi del turno morto. Pura (letture fs esplicite nei parametri).
 * opts: {auditFile, logDir, stateFile, findingsFile, tail}
 * Ritorna { ok, reconstruction, dead_turn, advice, sources }.
 */
function plan(opts) {
  opts = opts || {};
  const auditFile = resolveFile(opts.auditFile, 'RUN_AUDIT_FILE', path.join(WS, 'reports', 'tmp', 'run-audit.jsonl'));
  const logDir = opts.logDir || process.env.WORKFLOW_LOG_DIR || path.join(WS, 'reports', 'tmp', 'workflow');
  const stateFile = resolveFile(opts.stateFile, 'OPSTATE_FILE', path.join(WS, 'operation-state.json'));
  const findingsFile = resolveFile(opts.findingsFile, 'FINDINGS_JSONL', path.join(WS, 'reports', 'findings.jsonl'));

  const audit = readJsonl(auditFile);
  const tail = Math.max(1, opts.tail || 8);
  const recent = audit.slice(-tail);
  const classified = classifyEntries(recent);

  const workflows = latestWorkflowLogs(logDir);
  const state = readOpstate(stateFile);
  const findings = readJsonl(findingsFile);

  const lastTs = audit.length ? audit[audit.length - 1].ts : null;
  const failures = classified.filter((c) => c.blocked || (c.exit != null && c.exit !== 0));
  const last = classified[classified.length - 1];
  // Turno morto: l'ULTIMA invocazione è fallita/bloccata E nessuna transizione opstate dopo
  // di essa → il turno è morto senza progresso. Ricostruire, mai rigiocare.
  const noProgress = !state.transitions.length || (lastTs && state.transitions[state.transitions.length - 1].ts < lastTs);
  const deadTurn = !!last && (last.blocked || (last.exit != null && last.exit !== 0)) && noProgress;

  const advice = [];
  const seen = new Set();
  for (const f of failures) {
    if (!f.recovery || seen.has(f.recovery.action)) continue;
    seen.add(f.recovery.action);
    advice.push({ action: f.recovery.action, hint: f.recovery.hint, from: `${f.bin} (${f.error_class})` });
  }
  if (deadTurn) {
    advice.push({ action: 'recover_from_artifacts', hint: 'turno morto rilevato: NON rigiocare le azioni; ricostruisci lo stato dagli artefatti (audit/workflow/opstate) e riparti dal prossimo step valido', from: 'recover.js' });
  }
  if (!advice.length) advice.push({ action: 'continue', hint: 'nessun errore bloccante nelle ultime ' + tail + ' invocazioni: si può continuare', from: 'recover.js' });

  const reconstruction = {
    audit_lines: audit.length,
    last_invocation_ts: lastTs,
    recent_invocations: classified,
    workflow_logs: workflows.map((w) => ({
      file: w.file, ok: !!(w.summary && w.summary.ok), steps_total: w.steps_total, failed_steps: w.failed_steps,
    })),
    opstate: { revision: state.revision, transitions: state.transitions.length, leases: Object.keys(state.leases) },
    findings_count: findings.length,
  };
  return {
    ok: true, dead_turn: deadTurn, reconstruction, advice,
    sources: { auditFile, logDir, stateFile, findingsFile },
  };
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (cmd !== 'plan') {
    console.error('usage: node tools/recover.js plan [--audit <f>] [--logdir <d>] [--state <f>] [--findings <f>] [--tail N] [--json]');
    process.exit(2);
  }
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
  const r = plan({
    auditFile: opt('--audit'), logDir: opt('--logdir'), stateFile: opt('--state'),
    findingsFile: opt('--findings'), tail: parseInt(opt('--tail'), 10) || undefined,
  });
  console.log(JSON.stringify(r, null, argv.includes('--json') ? 2 : 0));
  process.exit(r.dead_turn ? 1 : 0); // turno morto = exit 1 (serve attenzione, non replay)
}

if (require.main === module) process.exit(main());
module.exports = { plan, classifyEntries, readJsonl, latestWorkflowLogs, readOpstate };
