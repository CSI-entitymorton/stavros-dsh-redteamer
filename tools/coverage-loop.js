#!/usr/bin/env node
// Tier 1-C — Coverage-driven completeness.
//
// The asset graph tells us which surfaces EXIST on a target; the coverage matrix tells us
// which vulnerability classes have been TESTED. This module joins the two: for each host it
// derives the vuln classes RELEVANT to its discovered surfaces (an HTTP service makes sqli/
// xss/idor/... relevant; SMB makes network/authn/config relevant; ...), subtracts what
// coverage already marks tested/confirmed, and reports the GAP. That gap is the worklist that
// turns "test until I feel done" into "test until the discovered surface is fully covered".
//
// It is a MEASURE + a STOP CONDITION, not an executor: pair it with tools/next-actions.js to
// fill the gaps, re-ingest results into the model (tools/target-model.js), recompute, and stop
// when remaining()==0 or isDry() (K rounds with no reduction). Purely additive; reuses the
// canonical coverage.buildMatrix (per-host entities) so the class semantics stay identical.
//
// CLI:
//   node tools/coverage-loop.js gaps [--json]     # per-host {relevant, covered, gaps, coverage_pct}
//   node tools/coverage-loop.js report            # markdown summary
//   (exit 1 if any gap remains — usable as a completeness gate; exit 0 if fully covered)
//
// Env: STATE_DB (model), COVERAGE_REPORTS_DIR + FINDINGS_JSONL (coverage sources; default reports/).
'use strict';

const fs = require('fs');
const path = require('path');
const coverage = require('./coverage');
const tm = require('./target-model');

const WS = path.join(__dirname, '..');
const reportsDir = () => process.env.COVERAGE_REPORTS_DIR || path.join(WS, 'reports');
const findingsFile = () => process.env.FINDINGS_JSONL || path.join(reportsDir(), 'findings.jsonl');

// Which vuln classes each discovered surface makes RELEVANT (i.e. worth testing). Kept
// conservative: a class is relevant only when a surface that could exhibit it is present.
const SURFACE_CLASSES = {
  base: ['network', 'config'],
  http: ['info-disclosure', 'injection', 'sqli', 'xss', 'idor', 'authn', 'authz', 'csrf', 'path-traversal', 'file-upload'],
  smb: ['network', 'authn', 'config', 'info-disclosure'],
  ldap: ['authn', 'info-disclosure', 'config'],
  db: ['authn', 'config', 'injection', 'info-disclosure'],
  ssh: ['authn', 'config', 'crypto'],
};

// A concrete probe suggestion per class — the "how" to close a gap (goes through run.js).
const GAP_PROBE = {
  network: 'node tools/run.js nmap -sV --top-ports 1000 <host>',
  config: 'node tools/run.js nuclei -u <url> -tags misconfig,default-login -jsonl',
  'info-disclosure': 'node tools/run.js nuclei -u <url> -tags exposure,disclosure -jsonl',
  injection: 'node tools/run.js nuclei -u <url> -tags injection -jsonl',
  sqli: 'node tools/run.js sqlmap -u <url> --batch --level 1 --risk 1',
  xss: 'node tools/run.js dalfox url <url>',
  idor: 'manual: enumerare oggetti/ID con sessione autorizzata (repeater)',
  authn: 'node tools/run.js nuclei -u <url> -tags auth-bypass,default-login -jsonl',
  authz: 'manual: verificare controlli di accesso tra ruoli (repeater)',
  csrf: 'node tools/run.js nuclei -u <url> -tags csrf -jsonl',
  'path-traversal': 'node tools/run.js ffuf -u <url>/FUZZ -w <wordlist> ; nuclei -tags lfi',
  'file-upload': 'manual: testare upload non ristretti (repeater)',
  crypto: 'node tools/run.js nuclei -u <url> -tags ssl,tls -jsonl',
};

function relevantClasses(target) {
  const set = new Set(SURFACE_CLASSES.base);
  const ports = (target.hosts || []).flatMap((h) => (h.ports || []).filter((p) => p.state === 'open'));
  const has = (nums, re) => ports.some((p) => nums.includes(p.port) || (re && re.test(p.service || '')));
  const httpEp = (target.endpoints || []).some((e) => /^https?:/i.test(e.url));
  if (httpEp || has([80, 443, 8080, 8443, 8000], /https?|http-proxy/i)) SURFACE_CLASSES.http.forEach((c) => set.add(c));
  if (has([445, 139], /smb|microsoft-ds|netbios/i)) SURFACE_CLASSES.smb.forEach((c) => set.add(c));
  if (has([389, 636, 3268], /ldap/i)) SURFACE_CLASSES.ldap.forEach((c) => set.add(c));
  if (has([21, 3306, 1433, 5432, 6379, 27017, 1521], /ftp|mysql|mssql|postgres|redis|mongo|oracle/i)) SURFACE_CLASSES.db.forEach((c) => set.add(c));
  if (has([22], /ssh/i)) SURFACE_CLASSES.ssh.forEach((c) => set.add(c));
  return [...set];
}

// Per-host typed Vuln entities from the model (host-scoped, so coverage never bleeds across hosts).
function hostEntities(target) {
  return (target.vulns || [])
    .filter((v) => coverage.CLASSES.includes(v.class))
    .map((v, i) => ({ entityType: 'Vuln', id: `${target.host}:${v.template_id || v.class}:${i}`, surface_ref: v.url || v.host || target.host, class: v.class }));
}

// computeGaps(target, opts) — pure: one snapshot target -> gap report.
function computeGaps(target, opts) {
  opts = opts || {};
  const relevant = relevantClasses(target);
  const m = coverage.buildMatrix(target.host, {
    entities: hostEntities(target),
    reportsDir: opts.reportsDir || reportsDir(),
    findingsFile: opts.findingsFile || findingsFile(),
  });
  const statusByClass = {};
  m.rows.forEach((r) => { statusByClass[r.class] = r.status; });
  const covered = relevant.filter((c) => ['confirmed', 'tested'].includes(statusByClass[c]));
  const gaps = relevant.filter((c) => !covered.includes(c));
  return {
    host: target.host,
    relevant,
    covered,
    gaps,
    coverage_pct: relevant.length ? Math.round((100 * covered.length) / relevant.length) : 100,
    status_by_class: statusByClass,
  };
}

function gapsFromDb(db, opts) {
  const snap = tm.snapshot(db);
  return snap.targets.map((t) => computeGaps(t, opts));
}

// The "how to close it" list for one host's gaps.
function nextForGaps(gapReport) {
  return gapReport.gaps.map((c) => ({ class: c, probe: GAP_PROBE[c] || 'manual review' }));
}

// Loop bookkeeping.
function remaining(reports) { return reports.reduce((n, r) => n + r.gaps.length, 0); }
// Dry when a round did not reduce the total gap count (no forward progress).
function isDry(prevRemaining, curRemaining) { return curRemaining >= prevRemaining; }

function reportTable(reports) {
  const lines = ['# Completeness — coverage vs discovered surface', ''];
  for (const r of reports) {
    lines.push(`## ${r.host}  —  ${r.coverage_pct}% (${r.covered.length}/${r.relevant.length})`);
    lines.push(r.gaps.length ? `- **gap (${r.gaps.length})**: ${r.gaps.join(', ')}` : '- ✅ nessun gap sulla superficie scoperta');
    for (const s of nextForGaps(r)) lines.push(`  - ${s.class}: \`${s.probe}\``);
    lines.push('');
  }
  lines.push(`Totale gap residui: ${remaining(reports)}`);
  return lines.join('\n');
}

module.exports = {
  relevantClasses, hostEntities, computeGaps, gapsFromDb, nextForGaps,
  remaining, isDry, reportTable, SURFACE_CLASSES, GAP_PROBE,
};

// ------------------------------------------------------------------ CLI
if (require.main === module) {
  const args = process.argv.slice(2);
  const cmd = args[0] && !args[0].startsWith('--') ? args[0] : 'gaps';
  const db = tm.open();
  try {
    const reports = gapsFromDb(db, {});
    if (cmd === 'gaps') {
      console.log(JSON.stringify(reports, null, args.includes('--json') ? 0 : 2));
    } else if (cmd === 'report') {
      console.log(reportTable(reports));
    } else {
      console.error('usage: coverage-loop.js <gaps [--json] | report>');
      process.exit(2);
    }
    process.exit(remaining(reports) > 0 ? 1 : 0);
  } finally {
    if (db && typeof db.close === 'function') db.close();
  }
}
