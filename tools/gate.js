#!/usr/bin/env node
// Stage-gate structural validation for the Stavros harness.
//   node tools/gate.js status <host>     # show passed/missing gates per phase
//   node tools/gate.js pass <phase>      # validate criteria and write pass to gate-log.md
//   node tools/gate.js check <phase>     # check if a gate is passed (exit 0/1)
//   ... [--workflow <file.yaml>]  (o env GATE_WORKFLOW_FILE)
//
// E3 (Ondata 4): i file attesi dalle fasi possono essere DICHIARATIVI — sezione `reports:`
// del dialetto workflow (tools/workflow.js), consumata qui con --workflow/GATE_WORKFLOW_FILE.
// Se la fase dichiara reports:, i check kind 'file' hardcoded della fase vengono SOSTITUITI
// dai report dichiarati (fail-closed: report dichiarato ma mancante → FAIL). Fasi senza
// reports: → comportamento legacy (elenco hardcoded). I check chain/oracle/evidenceQuote di
// SA1 NON vengono mai toccati (coordinazione SA1 rispettata).
//
// Pattern adapted from SeaOf0/dsh-redteam-model (MIT) — plugins/dsh-stage-gate.
// Gate phases: recon → map → test → authed → chains → report.
// Gate-log format: `| iso | mode/phase | pass | criteria | ... |` (append-only).

'use strict';
const fs = require('fs');
const path = require('path');

// GATE_WS: workspace-root override per i test (fixture in mkdtemp, MAI il workspace reale);
// default = package root (i tool idratati nel workspace risolvono qui in produzione).
const WS = () => process.env.GATE_WS || path.join(__dirname, '..');
const REPORTS = () => path.join(WS(), 'reports');
// GATE_LOG_FILE: override per i test (fixture in mkdtemp, MAI il gate-log reale).
const GATE_LOG = () => process.env.GATE_LOG_FILE || path.join(REPORTS(), 'gate-log.md');
const MODE = 'stavros';

// ─── Gate definitions (structural checks, never model judgement) ───
// Each gate has:
//   - checks: array of { kind: "file"|"markers"|"table"|"findings"|"verify"|"chain"|"oracle"|"evidenceQuote", args }
//   - manual: human-review items (the model must confirm, never auto-check)
// Ondata1 additions to the report gate (additive — original semantics unchanged):
//   chain         → findings.jsonl hash-chain intact (A3); legacy unchained prefix is
//                   informational ('unchained-legacy'), a break fails the gate;
//   oracle        → every reality-level finding (confirmed/verified/exploited/proven_impact)
//                   re-has its mechanical oracle validated against DISK now (A1);
//   evidenceQuote → reality-level findings carry an evidence_quote whose text is a verbatim
//                   substring of the referenced artifact (A2).
const GATES = {
  recon: {
    title: 'Reconnaissance baseline',
    checks: [
      { kind: 'file', file: 'scope.json', hint: 'scope.json exists' },
      { kind: 'scopeNonEmpty', hint: 'scope.json has allowed_hosts or allowed_ips' },
    ],
    manual: ['Scope entries carry written authorization (pentest agreed / in-scope bounty / own lab)'],
  },
  map: {
    title: 'Service enumeration baseline',
    checks: [
      { kind: 'file', file: 'reports/tmp/run-audit.jsonl', hint: 'at least one scan run' },
      { kind: 'findings', min: 1, hint: 'at least one finding recorded' },
    ],
    manual: ['All in-scope hosts have been enumerated (ports + services)'],
  },
  test: {
    title: 'Vulnerability testing baseline',
    checks: [
      { kind: 'findings', min: 1, hint: 'findings recorded' },
      { kind: 'markers', file: 'reports/gate-log.md', markers: ['stavros/map'], hint: 'map gate passed' },
    ],
    manual: ['Each vulnerability class (sql/injection/authz/xss/ssrf/...) has been tested or intentionally skipped with rationale'],
  },
  authed: {
    title: 'Authenticated post-auth baseline',
    checks: [
      { kind: 'file', file: 'auth.json', hint: 'auth.json exists' },
    ],
    manual: ['Authenticated surface tested (or skipped because no credentials)'],
  },
  chains: {
    title: 'Exploit chain coverage',
    checks: [
      { kind: 'findings', min: 1, hint: 'findings recorded' },
    ],
    manual: ['Chains built from low/medium findings that escalate to high impact'],
  },
  report: {
    title: 'Report readiness (P3)',
    checks: [
      { kind: 'findings', min: 1, hint: 'findings recorded' },
      { kind: 'verify', min: 1, hint: 'at least one finding verified' },
      { kind: 'noPending', hint: 'no finding with status pending' },
      { kind: 'coverage', hint: 'coverage matrix prepared' },
      // Ondata1 A1/A2/A3 — fail-closed evidence quality (additive):
      { kind: 'chain', hint: 'findings.jsonl hash-chain intact' },
      { kind: 'oracle', hint: 'reality findings carry a disk-valid mechanical oracle' },
      { kind: 'evidenceQuote', hint: 'reality findings quote an exact artifact slice' },
      // Ondata 6 (additivo, SA1 invariato): la coda del gate cresce solo in coda —
      // test-gate-chain asserisce slice(0,4) legacy + slice(4) SA1 e viene aggiornato di conseguenza.
      { kind: 'pocReplay', hint: 'every verified finding has a reproducer exp/<id>.py on disk' },
      { kind: 'chainHead', hint: 'findings chain head matches the external head-anchor log' },
    ],
    manual: ['Coverage matrix complete — every class tested or marked N/A with rationale', 'Cross-check done: independent subagent reviewed the findings'],
  },
};

// ─── Helpers ───

function loadJsonl(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch { return []; }
}

function readText(file) {
  try {
    const full = path.isAbsolute(file) ? file : path.resolve(path.join(WS(), file));
    return fs.readFileSync(full, 'utf8');
  } catch { return ''; }
}

function gateLog() {
  return readText('reports/gate-log.md');
}

// ─── Check runners ───

function checkFile(file) {
  const full = path.resolve(path.join(WS(), file));
  const ok = fs.existsSync(full);
  return { ok, detail: ok ? `${file} exists` : `${file} missing` };
}

function checkMarkers(file, markers) {
  const text = readText(file);
  const found = markers.filter((m) => text.includes(m));
  return { ok: found.length === markers.length, detail: `markers [${markers.join(', ')}] in ${file}: ${found.length}/${markers.length}` };
}

function checkFindings(min) {
  const findings = loadJsonl(path.join(REPORTS(), 'findings.jsonl'));
  return { ok: findings.length >= min, detail: `findings: ${findings.length} >= ${min}` };
}

function checkVerify(min) {
  const findings = loadJsonl(path.join(REPORTS(), 'findings.jsonl'));
  const verified = findings.filter((f) => f.status === 'verified' || f.verified);
  return { ok: verified.length >= min, detail: `verified findings: ${verified.length} >= ${min}` };
}

function checkNoPending() {
  const findings = loadJsonl(path.join(REPORTS(), 'findings.jsonl'));
  const pending = findings.filter((f) => f.status === 'pending' || (!f.status && !f.verified));
  return { ok: pending.length === 0, detail: `pending findings: ${pending.length}` };
}

function checkCoverage() {
  const cov = readText('reports/coverage-matrix.md');
  const ok = cov.includes('|') && cov.includes('|');
  return { ok, detail: ok ? 'coverage-matrix.md has table rows' : 'coverage-matrix.md missing or empty' };
}

// Dual-schema scope normalization (additive): accepts the classic {allowed_hosts,allowed_ips}
// shape AND the lab shape {targets,exclusions} used by tools/scope-guard.js normalizeScope.
// Purely a superset — nothing that passed before can fail now; exclusions alone authorize
// nothing (an empty allowlist still fails). Accepts an injected scope object for offline tests;
// reads <ws>/scope.json when omitted.
function checkScopeNonEmpty(scopeObj) {
  let s = scopeObj;
  if (s == null) {
    try { s = JSON.parse(readText('scope.json')); } catch {
      return { ok: false, detail: 'scope.json unreadable' };
    }
  }
  try {
    const hosts = (s.allowed_hosts || []).length;
    const ips = (s.allowed_ips || []).length;
    const targets = Array.isArray(s.targets) ? s.targets.length : 0;
    const excl = Array.isArray(s.exclusions) ? s.exclusions.length : 0;
    const ok = hosts + ips + targets > 0;
    return { ok, detail: `scope.json: ${hosts} hosts, ${ips} IPs/CIDRs${targets ? `, ${targets} targets` : ''}${excl ? `, ${excl} exclusions` : ''}` };
  } catch {
    return { ok: false, detail: 'scope.json unreadable' };
  }
}

// ─── Ondata1 A1/A2/A3 checks ───
// All three take an optional findings.jsonl path (default: workspace reports/findings.jsonl)
// so tests can run them against temp fixtures without touching the real store.
const FINDINGS_FILE = () => path.join(REPORTS(), 'findings.jsonl');

function loadRawLines(file) {
  try { return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean); } catch { return []; }
}

function checkChain(file) {
  file = file || FINDINGS_FILE();
  const lines = loadRawLines(file);
  if (!lines.length) return { ok: true, detail: 'findings.jsonl empty/absent — nothing chained yet' };
  const r = require('./record-finding').verifyFindingsChain(lines);
  if (!r.ok) return { ok: false, detail: `findings chain BROKEN at line ${r.index + 1}: ${r.reason}` };
  return { ok: true, detail: `findings chain intact: ${r.chained} chained, ${r.legacy} unchained-legacy (informational)` };
}

function realityOffenders(file, validateFn) {
  const findings = loadJsonl(file);
  const checked = [];
  const failed = [];
  for (const f of findings) {
    if (!require('./oracle').claimingReality(f)) continue;
    const err = validateFn(f);
    checked.push(f.title || f.host || '?');
    if (err) failed.push(`${f.title || f.host || '?'}: ${err}`);
  }
  return { checked, failed };
}

function checkOracle(file) {
  file = file || FINDINGS_FILE();
  const { checked, failed } = realityOffenders(file, (f) => require('./oracle').validateOracle(f.oracle));
  if (!checked.length) return { ok: true, detail: 'no reality-level findings to oracle-check' };
  const ok = failed.length === 0;
  return { ok, detail: `oracle re-validated on disk: ${checked.length - failed.length}/${checked.length} pass${failed.length ? ' — ' + failed[0] : ''}` };
}

function checkEvidenceQuote(file) {
  file = file || FINDINGS_FILE();
  const { checked, failed } = realityOffenders(file, (f) => require('./evidence-quote').validateQuote(f));
  if (!checked.length) return { ok: true, detail: 'no reality-level findings to quote-check' };
  const ok = failed.length === 0;
  return { ok, detail: `evidence quotes verbatim on disk: ${checked.length - failed.length}/${checked.length} pass${failed.length ? ' — ' + failed[0] : ''}` };
}

function checkPocReplay(file) {
  file = file || FINDINGS_FILE();
  const findings = loadJsonl(file);
  const r = require('./poc-replay').checkPocReplays(findings);
  if (!findings.length) return { ok: true, detail: 'no findings yet — pocReplay vacuous' };
  const ok = r.ok;
  return { ok, detail: ok
    ? `poc replays: ${r.checked.length} verified finding(s) with reproducer on disk`
    : `missing reproducer exp/<id>.py for: ${r.missingExp.join(', ')}` };
}

function checkChainHead(opts) {
  const r = require('./record-finding').verifyHeadAnchor(opts);
  return { ok: !!r.ok, detail: r.detail || (r.ok ? 'head anchor ok' : 'head anchor mismatch') };
}

function runCheck(check) {
  switch (check.kind) {
    case 'file': return checkFile(check.file);
    case 'markers': return checkMarkers(check.file, check.markers);
    case 'findings': return checkFindings(check.min);
    case 'verify': return checkVerify(check.min);
    case 'noPending': return checkNoPending();
    case 'coverage': return checkCoverage();
    case 'scopeNonEmpty': return checkScopeNonEmpty();
    case 'chain': return checkChain(check.file);
    case 'oracle': return checkOracle(check.file);
    case 'evidenceQuote': return checkEvidenceQuote(check.file);
    case 'pocReplay': return checkPocReplay(check.file);
    case 'chainHead': return checkChainHead();
    default: return { ok: false, detail: `unknown check kind: ${check.kind}` };
  }
}

// E3: quando la fase dichiara reports: (workflow), i check kind 'file' hardcoded vengono
// SOSTITUITI dai report dichiarati; gli altri check (incl. SA1 chain/oracle/evidenceQuote)
// restano. Fasi senza dichiarazioni → elenco hardcoded (legacy byte-identico).
function gateChecks(gateId, workflowReports) {
  const gate = GATES[gateId];
  const declared = workflowReports && workflowReports[gateId];
  if (!declared || !declared.length) return gate.checks;
  const nonFile = gate.checks.filter((c) => c.kind !== 'file');
  const declaredChecks = declared.map((r) => ({
    kind: 'file', file: r.path,
    hint: `declared report${r.type ? ' (' + r.type + ')' : ''}${r.surface ? ', surface ' + r.surface : ''}`,
    declared: true, surface: r.surface || null, type: r.type || null,
  }));
  return [...nonFile, ...declaredChecks];
}

function runGate(gateId, opts) {
  opts = opts || {};
  const gate = GATES[gateId];
  if (!gate) return null;
  const checks = gateChecks(gateId, opts.workflowReports);
  const results = checks.map(runCheck);
  const allOk = results.every((r) => r.ok);
  return { gateId, title: gate.title, allOk, results, manual: gate.manual, checks };
}

// Carica i reports: dichiarati da un workflow (dialetto workflow.js). Fail-closed: YAML
// malformato o dialetto invalido → errore esplicito, mai fallback silenzioso al legacy.
function loadWorkflowReports(file) {
  const wf = require('./workflow');
  let loaded;
  try { loaded = wf.loadWorkflow(file); }
  catch (e) { throw new Error(`workflow load failed (${file}): ${e.message}`); }
  const errs = wf.validateDoc(loaded.doc);
  if (errs.length) throw new Error(`workflow invalid (${file}): ${errs.join('; ')}`);
  return (loaded.doc && loaded.doc.reports) || {};
}

function gateLogHasPass(logText, gateId) {
  const needle = `${MODE}/${gateId}`;
  for (const line of String(logText ?? '').split('\n')) {
    if (!line.includes('|')) continue;
    const cells = line.split('|').map((c) => c.trim());
    if (cells.includes(needle) && cells.includes('pass')) return true;
  }
  return false;
}

function appendGateLog(gateId, verdict, detail) {
  const line = `| ${new Date().toISOString()} | ${MODE}/${gateId} | ${verdict} | ${detail} |`;
  try {
    fs.mkdirSync(path.dirname(GATE_LOG()), { recursive: true });
    fs.appendFileSync(GATE_LOG(), line + '\n');
  } catch {}
}

// ─── CLI ───

function cmdStatus(host, workflowFile) {
  const ws = WS();
  let workflowReports = null;
  if (workflowFile) {
    try { workflowReports = loadWorkflowReports(workflowFile); } catch (e) { console.error('[gate] ' + e.message); process.exit(1); }
  }
  for (const [id, gate] of Object.entries(GATES)) {
    const r = runGate(id, { workflowReports });
    const passed = gateLogHasPass(readText(GATE_LOG()), id);
    const status = passed ? '✔ PASS' : '✗ MISS';
    console.log(`${status} ${id} — ${gate.title}`);
    if (!passed) {
      for (const c of r.results) {
        if (!c.ok) console.log(`     ${c.detail}`);
      }
    }
  }
}

function cmdPass(gateId, workflowFile) {
  const gate = GATES[gateId];
  if (!gate) {
    console.error(`unknown gate: ${gateId}. Valid: ${Object.keys(GATES).join(', ')}`);
    process.exit(2);
  }
  let workflowReports = null;
  if (workflowFile) {
    try { workflowReports = loadWorkflowReports(workflowFile); } catch (e) { console.error('[gate] ' + e.message); process.exit(1); }
  }
  const r = runGate(gateId, { workflowReports });
  if (r.allOk) {
    const detail = r.results.map((c) => c.detail).join('; ');
    appendGateLog(gateId, 'pass', detail);
    console.log(`[gate] PASS ${gateId} — ${gate.title}`);
    process.exit(0);
  } else {
    for (const c of r.results) {
      if (!c.ok) console.error(`[gate] FAIL: ${c.detail}`);
    }
    console.error(`[gate] ${gateId} gate NOT passed — fix the criteria above`);
    process.exit(1);
  }
}

function cmdCheck(gateId) {
  const passed = gateLogHasPass(readText(GATE_LOG()), gateId);
  if (passed) { console.log(`[gate] ${gateId} PASS`); process.exit(0); }
  else { console.log(`[gate] ${gateId} MISS`); process.exit(1); }
}

function main() {
  const args = process.argv.slice(2);
  const wfIndex = args.indexOf('--workflow');
  const workflowFile = wfIndex >= 0 ? args[wfIndex + 1] : (process.env.GATE_WORKFLOW_FILE || null);
  const cmd = args[0];
  if (cmd === 'status' && args[1]) {
    cmdStatus(args[1], workflowFile);
  } else if (cmd === 'pass' && args[1]) {
    cmdPass(args[1], workflowFile);
  } else if (cmd === 'check' && args[1]) {
    cmdCheck(args[1]);
  } else {
    console.error('usage: node tools/gate.js <status <host> | pass <phase> | check <phase>> [--workflow <file.yaml>]');
    console.error('phases: ' + Object.keys(GATES).join(', '));
    process.exit(2);
  }
}

if (require.main === module) main();

module.exports = { GATES, runGate, gateChecks, loadWorkflowReports, gateLogHasPass, checkFile, checkMarkers, checkFindings, checkVerify, checkNoPending, checkCoverage, checkScopeNonEmpty, checkChain, checkOracle, checkEvidenceQuote, checkPocReplay, checkChainHead };