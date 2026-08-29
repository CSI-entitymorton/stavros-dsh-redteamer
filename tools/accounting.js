#!/usr/bin/env node
// F8 + C4w (Ondata 4) — accounting token/costo per azione/agente, visibilità costo per
// ingaggio, abilita i budget-gate negli stage P1-P3 (spec §3.1 F8 + §3.3 C5).
//
// Regole (vincoli di handoff, INNEGOCIABILI):
//   - ZERO rete, ZERO dipendenze: il calcolo usa campi esistenti (ts, bin, durata) e i token
//     SOLO se forniti esplicitamente (--tokens / env / file). MAI chiamate a API di pricing.
//   - ADDITIVO: `usage` è un campo NUOVO sui record nuovi (audit run.js / findings);
//     i record esistenti non vengono MAI modificati (romperebbero la hash-chain A3).
//   - Funzioni pure e idempotenti: stesso input → stesso output, nessuno stato.
//
// Formato usage (coerente ovunque):
//   usage: { tokens_in: <int>=0, tokens_out: <int>=0, cost: <number>|null, source: '<string>'|null }
//   cost è opzionale ("se noto"): arriva solo da env/file dell'operatore, mai calcolato.
//
// CLI:
//   node tools/accounting.js aggregate <audit.jsonl> [--json]
//       → { actions:{totals, per_bin}, agents:{totals, per_agent}, session:{...} }
//   node tools/accounting.js usage '<entry-json>'   # usage normalizzato di UNA entry
'use strict';
const fs = require('fs');

// --- usage normalization -----------------------------------------------------

const USAGE_KEYS = ['tokens_in', 'tokens_out', 'cost', 'source'];

function isNonNegNumber(v) { return typeof v === 'number' && Number.isFinite(v) && v >= 0; }

/**
 * Normalize the usage of ONE audit/finding entry. Sources, in order:
 *   1. entry.usage (object) — the explicit, additive field
 *   2. entry.tokens_in/entry.tokens_out/entry.cost (flat fields, accepted for compatibility)
 * Missing values default to 0 for tokens; cost stays null unless explicitly numeric.
 * Returns a canonical usage object (never throws; malformed input → zeros + source 'invalid').
 */
function entryUsage(entry) {
  const u = (entry && typeof entry === 'object' && entry.usage && typeof entry.usage === 'object') ? entry.usage : {};
  const flat = entry && typeof entry === 'object' ? entry : {};
  const tokensIn = isNonNegNumber(u.tokens_in) ? u.tokens_in : (isNonNegNumber(flat.tokens_in) ? flat.tokens_in : 0);
  const tokensOut = isNonNegNumber(u.tokens_out) ? u.tokens_out : (isNonNegNumber(flat.tokens_out) ? flat.tokens_out : 0);
  let cost = null;
  if (isNonNegNumber(u.cost)) cost = u.cost;
  else if (isNonNegNumber(flat.cost)) cost = flat.cost;
  const durationMs = isNonNegNumber(entry && entry.duration_ms) ? entry.duration_ms
    : (isNonNegNumber(entry && entry.ms) ? entry.ms : null);
  return {
    tokens_in: tokensIn,
    tokens_out: tokensOut,
    tokens: tokensIn + tokensOut,
    cost,
    duration_ms: durationMs,
    source: typeof u.source === 'string' ? u.source : null,
  };
}

function agentOf(entry) {
  const a = entry && (entry.agent || entry.agent_name || entry.agent_class);
  return (typeof a === 'string' && a.trim()) ? a.trim() : 'unknown';
}
function binOf(entry) {
  const b = entry && entry.bin;
  return (typeof b === 'string' && b.trim()) ? b.trim() : 'unknown';
}

function addUsage(acc, u) {
  acc.invocations += 1;
  acc.tokens_in += u.tokens_in;
  acc.tokens_out += u.tokens_out;
  acc.tokens += u.tokens;
  if (u.cost != null) { acc.cost = (acc.cost == null ? 0 : acc.cost) + u.cost; acc.cost_known += 1; }
  if (u.duration_ms != null) acc.duration_ms += u.duration_ms;
  return acc;
}

function newTotals() {
  return { invocations: 0, tokens_in: 0, tokens_out: 0, tokens: 0, cost: null, cost_known: 0, duration_ms: 0 };
}

/**
 * Aggregate audit lines (JSONL parsed array or raw text). Pure + idempotent.
 * Returns { actions:{totals, per_bin}, agents:{totals, per_agent}, session:{invocations, tokens, cost} }.
 */
function aggregateAll(linesOrText) {
  let lines = linesOrText;
  if (typeof linesOrText === 'string') {
    lines = linesOrText.split(/\r?\n/).filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  }
  if (!Array.isArray(lines)) lines = [];
  const actions = { totals: newTotals(), per_bin: {} };
  const agents = { totals: newTotals(), per_agent: {} };
  for (const entry of lines) {
    if (!entry || typeof entry !== 'object') continue;
    const u = entryUsage(entry);
    const bin = binOf(entry);
    const agent = agentOf(entry);
    addUsage(actions.totals, u);
    addUsage(agents.totals, u);
    actions.per_bin[bin] = actions.per_bin[bin] || newTotals();
    addUsage(actions.per_bin[bin], u);
    agents.per_agent[agent] = agents.per_agent[agent] || newTotals();
    addUsage(agents.per_agent[agent], u);
  }
  const session = {
    invocations: actions.totals.invocations,
    tokens: actions.totals.tokens,
    tokens_in: actions.totals.tokens_in,
    tokens_out: actions.totals.tokens_out,
    cost: actions.totals.cost,
    cost_known: actions.totals.cost_known,
  };
  return { actions, agents, session };
}

// --- I/O helper (offline, env-overridable) ------------------------------------

function loadAuditLines(file) {
  const f = file || process.env.RUN_AUDIT_FILE || require('path').join(__dirname, '..', 'reports', 'tmp', 'run-audit.jsonl');
  try {
    return fs.readFileSync(f, 'utf8').split(/\r?\n/).filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}

// --- CLI ---------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (cmd === 'aggregate') {
    const file = args[1];
    const r = aggregateAll(loadAuditLines(file));
    if (args.includes('--json')) console.log(JSON.stringify(r, null, 2));
    else {
      const s = r.session;
      console.log(`session: ${s.invocations} invocations · ${s.tokens} tokens (${s.tokens_in} in / ${s.tokens_out} out)${s.cost != null ? ` · cost ${s.cost}` : ' · cost n/a'}`);
      console.log(`per-action: ${Object.entries(r.actions.per_bin).map(([k, v]) => `${k}=${v.tokens}t/${v.invocations}x`).join(' · ')}`);
      console.log(`per-agent:  ${Object.entries(r.agents.per_agent).map(([k, v]) => `${k}=${v.tokens}t/${v.invocations}x`).join(' · ')}`);
    }
    return 0;
  }
  if (cmd === 'usage') {
    let e;
    try { e = JSON.parse(args[1] || ''); } catch (err) {
      console.log(JSON.stringify({ ok: false, error: 'invalid entry JSON: ' + err.message }));
      return 1;
    }
    console.log(JSON.stringify(entryUsage(e)));
    return 0;
  }
  console.error('usage: node tools/accounting.js aggregate <audit.jsonl> [--json] | usage \'<entry-json>\'');
  return 2;
}

if (require.main === module) process.exit(main());

module.exports = { entryUsage, aggregateAll, loadAuditLines, agentOf, binOf, newTotals, USAGE_KEYS };
