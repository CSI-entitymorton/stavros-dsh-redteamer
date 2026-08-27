#!/usr/bin/env node
// Coverage matrix for the Stavros harness: vulnerability-class × status per host.
//   node tools/coverage.js <host>            # matrix to stdout
//   node tools/coverage.js <host> --json     # machine-readable
//   node tools/coverage.js <host> --write    # write reports/coverage-matrix.md (report gate input)
//
// Pattern adapted from SeaOf0/dsh-redteam-model (MIT) — coverage-matrix semantics.
// A class that was tested without findings is "tested" (a negative result is a result), never
// blank; a class not touched is "missed" and blocks the report gate (P3).
//
// Sources: reports/<host>-map.json (candidates per class) + reports/findings.jsonl.

'use strict';
const fs = require('fs');
const path = require('path');

const REPORTS = path.join(__dirname, '..', 'reports');
const FINDINGS = path.join(REPORTS, 'findings.jsonl');

// Vulnerability classes tracked by the harness (matches knowledge.md methodology).
const CLASSES = [
  'sqli', 'xss', 'ssrf', 'injection', 'authn', 'authz', 'csrf', 'idor', 'file-upload',
  'path-traversal', 'deserialization', 'info-disclosure', 'config', 'crypto', 'logic',
  'chain', 'cloud', 'network', 'wireless', 'postex',
];

function loadJsonl(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch { return []; }
}

function classOf(f) {
  const t = String(f.cwe || f.title || f.type || '').toLowerCase();
  if (/sql|sqli/.test(t)) return 'sqli';
  if (/xss/.test(t)) return 'xss';
  if (/ssrf/.test(t)) return 'ssrf';
  if (/injection|command/.test(t)) return 'injection';
  if (/auth.*(bypass|reset|otp|session|jwt)|login/i.test(t)) return 'authn';
  if (/idor|bola/.test(t)) return 'idor';
  if (/authz|broken access|privilege/.test(t)) return 'authz';
  if (/csrf/.test(t)) return 'csrf';
  if (/upload/.test(t)) return 'file-upload';
  if (/travers|lfi/.test(t)) return 'path-traversal';
  if (/deserial/.test(t)) return 'deserialization';
  if (/disclos|leak|expos|directory listing/.test(t)) return 'info-disclosure';
  if (/config|misconfig|default cred/.test(t)) return 'config';
  if (/crypto|jwt|hash|weak key/.test(t)) return 'crypto';
  if (/logic|race|state|business/.test(t)) return 'logic';
  if (/chain/.test(t)) return 'chain';
  if (/cloud|aws|azure|gcp/.test(t)) return 'cloud';
  if (/network|port|smb|nfs/.test(t)) return 'network';
  if (/wireless|wifi|wpa/.test(t)) return 'wireless';
  if (/post|exfil|lateral|persist/.test(t)) return 'postex';
  return 'other';
}

/** Build the matrix for one host. */
function buildMatrix(host) {
  const mapFile = path.join(REPORTS, `${host}-map.json`);
  let candidates = {};
  try { candidates = JSON.parse(fs.readFileSync(mapFile, 'utf8')); } catch {}
  const findings = loadJsonl(FINDINGS).filter((f) => !host || f.host === host || String(f.host || '').includes(host));
  const byClass = {};
  for (const f of findings) {
    const c = classOf(f);
    byClass[c] = byClass[c] || [];
    byClass[c].push(f);
  }
  const rows = CLASSES.map((cls) => {
    const cand = candidates[cls] ?? candidates[cls + 's'] ?? 0;
    const found = byClass[cls] || [];
    let status = 'missed';
    if (found.length) status = 'confirmed';
    else if (cand > 0 || found.some((f) => f.status === 'inconclusive')) status = 'tested';
    else if (cand === 0 && Object.keys(candidates).length > 0) status = 'n-a'; // no candidates → N/A
    return { class: cls, candidates: cand, findings: found.length, status };
  });
  const other = byClass['other'] || [];
  return { host, rows, otherFindings: other.length };
}

function matrixTable(m) {
  const lines = ['# Coverage Matrix', '', `Host: ${m.host}`, '',
    '| Class | Candidates | Findings | Status |', '|---|---|---|---|'];
  for (const r of m.rows) {
    lines.push(`| ${r.class} | ${r.candidates} | ${r.findings} | ${r.status} |`);
  }
  lines.push('', `Other/uncategorized findings: ${m.otherFindings}`, '',
    `Status legend: tested = class probed (negative result counts) · confirmed = finding(s) · n-a = no candidate surface · missed = NOT tested (blocks report gate)`);
  return lines.join('\n');
}

function main() {
  const args = process.argv.slice(2);
  const host = args[0];
  if (!host) {
    console.error('usage: node tools/coverage.js <host> [--json|--write]');
    process.exit(2);
  }
  const m = buildMatrix(host);
  if (args.includes('--json')) {
    console.log(JSON.stringify(m, null, 2));
  } else {
    console.log(matrixTable(m));
  }
  if (args.includes('--write')) {
    const out = path.join(REPORTS, 'coverage-matrix.md');
    fs.writeFileSync(out, matrixTable(m) + '\n');
    console.log(`\nwrote ${out}`);
  }
  const missed = m.rows.filter((r) => r.status === 'missed').length;
  process.exit(missed ? 1 : 0);
}

if (require.main === module) main();

module.exports = { CLASSES, buildMatrix, classOf, matrixTable };