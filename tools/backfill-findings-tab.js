#!/usr/bin/env node
// Backfill the DSH "Findings" tab (dsh-redteam-results SQLite store) from reports/findings.jsonl.
//
//   node tools/backfill-findings-tab.js [--dry-run] [--jsonl <path>] [--session <id>]
//
// Reuses record-finding.js syncToFindingsTab (idempotent upsert keyed on host|endpoint|title),
// so re-running this script never duplicates rows. Rows are attributed to a dedicated
// "session-backfill" session so they never masquerade as live-session work; cross-session views
// (mode pages, per-domain) show them regardless. Invalid lines are skipped and reported.
const fs = require('fs');
const path = require('path');
const { validate, key, syncToFindingsTab } = require('./record-finding');

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const get = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
const jsonl = get('--jsonl') || process.env.FINDINGS_JSONL || path.join(__dirname, '..', 'reports', 'findings.jsonl');
const sessionId = get('--session') || 'session-backfill';

let lines;
try {
  lines = fs.readFileSync(jsonl, 'utf8').split('\n').filter(Boolean);
} catch (e) {
  console.error('cannot read ' + jsonl + ': ' + e.message);
  process.exit(1);
}

let ok = 0, invalid = 0, failed = 0;
const errors = [];
for (let i = 0; i < lines.length; i++) {
  let f;
  try { f = JSON.parse(lines[i]); } catch (e) {
    invalid++; errors.push(`line ${i + 1}: invalid JSON (${e.message})`); continue;
  }
  const err = validate(f);
  if (err) { invalid++; errors.push(`line ${i + 1} [${(f || {}).title || '?'}]: ${err}`); continue; }
  if (dryRun) { ok++; continue; }
  const r = syncToFindingsTab(f, { sessionId });
  if (r.tab_synced) ok++;
  else { failed++; errors.push(`line ${i + 1} [${f.title}]: tab_error ${r.tab_error}`); }
}

console.log(JSON.stringify({
  jsonl, dry_run: dryRun,
  total_lines: lines.length, synced: ok, skipped_invalid: invalid, write_failed: failed,
  session: dryRun ? undefined : sessionId,
}, null, 2));
if (errors.length) console.error('--- details ---\n' + errors.join('\n'));
process.exit(failed === 0 ? 0 : 1);
