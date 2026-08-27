#!/usr/bin/env node
// Stage-gate structural validation for the Stavros harness.
//   node tools/gate.js status <host>     # show passed/missing gates per phase
//   node tools/gate.js pass <phase>      # validate criteria and write pass to gate-log.md
//   node tools/gate.js check <phase>     # check if a gate is passed (exit 0/1)
//
// Pattern adapted from SeaOf0/dsh-redteam-model (MIT) — plugins/dsh-stage-gate.
// Gate phases: recon → map → test → authed → chains → report.
// Gate-log format: `| iso | mode/phase | pass | criteria | ... |` (append-only).

'use strict';
const fs = require('fs');
const path = require('path');

const REPORTS = path.join(__dirname, '..', 'reports');
const GATE_LOG = path.join(REPORTS, 'gate-log.md');
const MODE = 'stavros';

// ─── Gate definitions (structural checks, never model judgement) ───
// Each gate has:
//   - checks: array of { kind: "file"|"markers"|"table"|"findings"|"verify", args }
//   - manual: human-review items (the model must confirm, never auto-check)
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
  try { return fs.readFileSync(path.resolve(path.join(__dirname, '..', file)), 'utf8'); } catch { return ''; }
}

function gateLog() {
  return readText('reports/gate-log.md');
}

// ─── Check runners ───

function checkFile(file) {
  const full = path.resolve(path.join(__dirname, '..', file));
  const ok = fs.existsSync(full);
  return { ok, detail: ok ? `${file} exists` : `${file} missing` };
}

function checkMarkers(file, markers) {
  const text = readText(file);
  const found = markers.filter((m) => text.includes(m));
  return { ok: found.length === markers.length, detail: `markers [${markers.join(', ')}] in ${file}: ${found.length}/${markers.length}` };
}

function checkFindings(min) {
  const findings = loadJsonl(path.join(REPORTS, 'findings.jsonl'));
  return { ok: findings.length >= min, detail: `findings: ${findings.length} >= ${min}` };
}

function checkVerify(min) {
  const findings = loadJsonl(path.join(REPORTS, 'findings.jsonl'));
  const verified = findings.filter((f) => f.status === 'verified' || f.verified);
  return { ok: verified.length >= min, detail: `verified findings: ${verified.length} >= ${min}` };
}

function checkNoPending() {
  const findings = loadJsonl(path.join(REPORTS, 'findings.jsonl'));
  const pending = findings.filter((f) => f.status === 'pending' || (!f.status && !f.verified));
  return { ok: pending.length === 0, detail: `pending findings: ${pending.length}` };
}

function checkCoverage() {
  const cov = readText('reports/coverage-matrix.md');
  const ok = cov.includes('|') && cov.includes('|');
  return { ok, detail: ok ? 'coverage-matrix.md has table rows' : 'coverage-matrix.md missing or empty' };
}

function checkScopeNonEmpty() {
  try {
    const s = JSON.parse(readText('scope.json'));
    const hosts = (s.allowed_hosts || []).length;
    const ips = (s.allowed_ips || []).length;
    return { ok: hosts + ips > 0, detail: `scope.json: ${hosts} hosts, ${ips} IPs/CIDRs` };
  } catch {
    return { ok: false, detail: 'scope.json unreadable' };
  }
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
    default: return { ok: false, detail: `unknown check kind: ${check.kind}` };
  }
}

function runGate(gateId) {
  const gate = GATES[gateId];
  if (!gate) return null;
  const results = gate.checks.map(runCheck);
  const allOk = results.every((r) => r.ok);
  return { gateId, title: gate.title, allOk, results, manual: gate.manual };
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
    fs.mkdirSync(path.dirname(GATE_LOG), { recursive: true });
    fs.appendFileSync(GATE_LOG, line + '\n');
  } catch {}
}

// ─── CLI ───

function cmdStatus(host) {
  const ws = path.join(__dirname, '..');
  for (const [id, gate] of Object.entries(GATES)) {
    const r = runGate(id);
    const passed = gateLogHasPass(readText('reports/gate-log.md'), id);
    const status = passed ? '✔ PASS' : '✗ MISS';
    console.log(`${status} ${id} — ${gate.title}`);
    if (!passed) {
      for (const c of r.results) {
        if (!c.ok) console.log(`     ${c.detail}`);
      }
    }
  }
}

function cmdPass(gateId) {
  const gate = GATES[gateId];
  if (!gate) {
    console.error(`unknown gate: ${gateId}. Valid: ${Object.keys(GATES).join(', ')}`);
    process.exit(2);
  }
  const r = runGate(gateId);
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
  const passed = gateLogHasPass(readText('reports/gate-log.md'), gateId);
  if (passed) { console.log(`[gate] ${gateId} PASS`); process.exit(0); }
  else { console.log(`[gate] ${gateId} MISS`); process.exit(1); }
}

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (cmd === 'status' && args[1]) {
    cmdStatus(args[1]);
  } else if (cmd === 'pass' && args[1]) {
    cmdPass(args[1]);
  } else if (cmd === 'check' && args[1]) {
    cmdCheck(args[1]);
  } else {
    console.error('usage: node tools/gate.js <status <host> | pass <phase> | check <phase>>');
    console.error('phases: ' + Object.keys(GATES).join(', '));
    process.exit(2);
  }
}

if (require.main === module) main();

module.exports = { GATES, runGate, gateLogHasPass, checkFile, checkMarkers, checkFindings, checkVerify, checkNoPending, checkCoverage, checkScopeNonEmpty };