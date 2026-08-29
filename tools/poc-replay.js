#!/usr/bin/env node
// POC replay for the Stavros harness (Ondata 2 — B7): re-executes the stored reproducer
//   python3 reports/exp/<id>.py -u <target>
// read-only by convention (gen-poc.js generates -u/--target-required scripts whose exit 0
// means "reproduced"), captures exit code + marker, and APPENDS a machine-auditable row to
// evidence-index.md. The replay is evidence: it runs even when the reproduction FAILS, and
// the failure is recorded honestly.
//
//   node tools/poc-replay.js <finding-id|--latest> -u/--target <url|host> [--exp-dir <dir>]
//                            [--evidence-index <file>] [--json]
// Env overrides: EXP_DIR, EVIDENCE_INDEX_FILE, SCOPE_JSON (target scope check as everywhere).
//
// Safety:
//   - target is scope-checked (canonTarget+inScope / cidrInScope) BEFORE anything runs;
//     refusal = no exec + no evidence row.
//   - only `-u <target>` is forwarded to the script; there is NO way to pass extra flags
//     through this wrapper (the reproducer's own --dangerous stays opt-in INSIDE the script
//     and is never enabled from here).
//   - by default the TARGET IS NOT written into evidence-index.md (no real targets in
//     committed files); pass --with-target explicitly if the index is engagement-local.
//
// Gate hook — kind 'pocReplay' WIRED into tools/gate.js (Ondata 6, additive: appended AFTER
// the SA1 chain/oracle/evidenceQuote checks, which stay untouched). export checkPocReplays(
// findings) keeps the coupling low: the gate loads findings and calls this pure checker (no
// spawns inside — execution stays with the operator/orchestrator via replay()).

'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { loadScope, inScope, cidrInScope } = require('./scope-guard');

const WS_ROOT = path.join(__dirname, '..');
const REPORTS = path.join(WS_ROOT, 'reports');
const FINDINGS = process.env.FINDINGS_JSONL || path.join(REPORTS, 'findings.jsonl');
const DEFAULT_EXP_DIR = process.env.EXP_DIR || path.join(REPORTS, 'exp');
const DEFAULT_EI = process.env.EVIDENCE_INDEX_FILE || path.join(WS_ROOT, 'evidence-index.md');

function loadFindings(file) {
  try {
    return fs.readFileSync(file || FINDINGS, 'utf8').split('\n').filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}

function findingId(f) {
  return (f.id || `${(f.host || 'host').replace(/[^a-zA-Z0-9]/g, '_')}-${(f.title || 'finding').replace(/[^a-zA-Z0-9]/g, '_').slice(0, 24)}`).toLowerCase();
}

function pickFinding(arg, file) {
  const all = loadFindings(file);
  if (!all.length) return null;
  if (arg === '--latest') {
    const verified = all.filter((f) => f.status === 'verified' || f.verified);
    return verified.length ? verified[verified.length - 1] : all[all.length - 1];
  }
  return all.find((f) => findingId(f) === arg) || all.find((f) => String(f.id) === arg) || null;
}

function checkTargetScope(target, scope) {
  const t = String(target || '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(t)) {
    const v = cidrInScope(t, scope);
    return { ok: !!v.ok, reason: v.reason || '' };
  }
  const c = require('./scope-guard').canonTarget(/^https?:\/\//i.test(t) ? t : 'http://' + t);
  if (!c.ok) return { ok: false, reason: 'canon: ' + c.reason };
  const v = inScope(c.canonical, scope);
  return { ok: !!v.ok, reason: v.reason || '', canonical: c.canonical };
}

function nextEvidenceNumber(eiFile) {
  try {
    let max = 0;
    for (const m of fs.readFileSync(eiFile, 'utf8').matchAll(/^\|\s*E-(\d+)\s*\|/gm)) max = Math.max(max, parseInt(m[1], 10));
    return max + 1;
  } catch { return 1; }
}

/** Append one replay row; returns the evidence number used. Target recorded ONLY on opt-in. */
function appendEvidenceIndex(eiFile, row) {
  const n = nextEvidenceNumber(eiFile);
  const date = new Date().toISOString().slice(0, 10);
  const targetPart = row.withTarget ? ` target=\`${row.target}\`` : '';
  const line = `| E-${String(n).padStart(3, '0')} | ${date} | \`${row.scriptRel}\` | poc-replay id=${row.id} exit=${row.exit} marker=${row.marker}${targetPart}${row.note ? ' · ' + row.note : ''} | poc-replay |`;
  fs.mkdirSync(path.dirname(eiFile), { recursive: true });
  fs.appendFileSync(eiFile, line + '\n');
  return n;
}

/** Pure marker extraction: convention exit 0 = reproduced; text markers win over heuristics. */
function extractMarker(stdoutText, exitCode) {
  const t = String(stdoutText || '');
  if (/REPRODUCED/i.test(t) && !/NOT reproduced/i.test(t)) return 'REPRODUCED';
  if (/NOT reproduced/i.test(t)) return 'NOT_REPRODUCED';
  return exitCode === 0 ? 'EXIT_0' : 'NO_MARKER';
}

/**
 * Replay one finding's exp script. Returns {ok, id, script, exit, marker, evidenceNo}.
 * ok=false with reason on refusals (nothing executed, nothing appended).
 */
function replay(findingIdArg, target, opts) {
  opts = opts || {};
  const expDir = opts.expDir || DEFAULT_EXP_DIR;
  const eiFile = opts.evidenceIndex || DEFAULT_EI;
  const f = pickFinding(findingIdArg, opts.findingsFile);
  if (!f) return { ok: false, reason: `no finding for "${findingIdArg}"` };
  const id = findingId(f);
  const script = path.join(expDir, `${id}.py`);
  const scriptRel = path.relative(WS_ROOT, script);
  if (!fs.existsSync(script)) return { ok: false, id, reason: `reproducer not found: ${scriptRel}` };
  if (!String(target || '').trim()) return { ok: false, id, reason: 'missing -u/--target' };

  // Scope gate BEFORE any execution (fail-closed, same scope.json as run.js/repeater.js).
  let scope;
  try { scope = loadScope(); } catch (e) {
    return { ok: false, id, reason: `scope unreadable (${e.message}) — refusing to run (fail-closed)` };
  }
  const verdict = checkTargetScope(target, scope);
  if (!verdict.ok) return { ok: false, id, reason: `target out of scope or invalid: ${verdict.reason}` };

  const r = spawnSync('python3', [script, '-u', String(target)], { encoding: 'utf8', timeout: 120000 });
  const exit = r.status == null ? 1 : r.status;
  const marker = r.timedOut ? 'TIMEOUT' : extractMarker(r.stdout, exit);
  const note = r.timedOut ? 'timeout 120s' : undefined;
  const row = { id, scriptRel, exit, marker, target, withTarget: !!opts.withTarget, note };
  const evidenceNo = appendEvidenceIndex(eiFile, row);
  return { ok: true, id, script: scriptRel, exit, marker, evidenceNo, timedOut: !!r.timedOut, stdoutTail: String(r.stdout || '').split('\n').filter(Boolean).slice(-2).join(' | ').slice(0, 300), stderrTail: String(r.stderr || '').split('\n').filter(Boolean).slice(-2).join(' | ').slice(0, 300) };
}

/**
 * Gate-ready additive check (kind 'pocReplay', PROPOSED — see header): every VERIFIED finding
 * must have a reproducer on disk. Execution of each replay is left to the operator/orchestrator
 * (this function performs NO spawns so the gate stays offline-safe).
 */
function checkPocReplays(findings, opts) {
  opts = opts || {};
  const expDir = opts.expDir || DEFAULT_EXP_DIR;
  const checked = [];
  const missingExp = [];
  for (const f of findings || []) {
    if (f.status !== 'verified') continue;
    const id = findingId(f);
    const p = path.join(expDir, `${id}.py`);
    if (fs.existsSync(p)) checked.push(id);
    else missingExp.push(id);
  }
  return { ok: missingExp.length === 0, checked, missingExp };
}

function usage(code) {
  console.error('usage: node tools/poc-replay.js <finding-id|--latest> -u <target> [--exp-dir d] [--evidence-index f] [--with-target] [--json]');
  process.exit(code == null ? 2 : code);
}

function main() {
  const argv = process.argv.slice(2);
  // Proper value-aware parsing: option VALUES must never be mistaken for the finding id.
  let id = null; let target = null; let expDir = null; let eiFile = null;
  let withTarget = false; let jsonOut = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-u' || a === '--target') { target = argv[++i]; continue; }
    if (a === '--exp-dir') { expDir = argv[++i]; continue; }
    if (a === '--evidence-index') { eiFile = argv[++i]; continue; }
    if (a === '--with-target') { withTarget = true; continue; }
    if (a === '--json') { jsonOut = true; continue; }
    if (a === '-h' || a === '--help') usage(0);
    if (!id) id = a;
  }
  if (!id || !target) usage(2);
  const res = replay(id, target, {
    expDir,
    evidenceIndex: eiFile,
    findingsFile: process.env.FINDINGS_JSONL,
    withTarget,
  });
  if (!res.ok) {
    console.error(JSON.stringify({ ok: false, error: res.reason }));
    process.exit(1);
  }
  if (jsonOut) {
    console.log(JSON.stringify(res, null, 2));
  } else {
    console.log(`[poc-replay] ${res.id}: exit=${res.exit} marker=${res.marker} → evidence-index #E-${String(res.evidenceNo).padStart(3, '0')}`);
  }
  // Exit-code contract mirrors the script convention: 0 = reproduced.
  process.exit(res.exit === 0 ? 0 : (res.exit > 0 && res.exit <= 2 ? res.exit : 1));
}

if (require.main === module) main();
module.exports = { replay, pickFinding, findingId, extractMarker, checkPocReplays, checkTargetScope, appendEvidenceIndex };
