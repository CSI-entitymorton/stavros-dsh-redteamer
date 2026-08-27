#!/usr/bin/env node
// Daily harness maintenance (repo-vet churchofmalware follow-ups). Runs once per day from
// cron/systemd; safe to run manually. Idempotent, offline-tolerant: every step reports its
// own failure and never blocks the others.
//
//   node tools/daily-maintenance.js [--skip-vendor] [--skip-kb]
//
// Steps:
//   1. threatintel: refresh the CISA KEV catalog + NVD/EPSS/KEV for every CVE found in
//      reports/findings.jsonl (+ optional extra ids in reports/ti-watchlist.txt, one per line).
//      After a refresh record-finding.js compiles kev:true/false, precise CWEs and references.
//   2. vendor-mirror: re-pull every repo already pinned in vendor/mirror/MANIFEST.jsonl
//      (unchanged SHA = cached no-op; new upstream commit = new pinned zip) + re-verify all
//      hashes + rebuild vendor/poc-archive/index.json.
//   3. kb-search: rebuild the FTS5 index over knowledge.md/docs (reports included).
const fs = require('fs');
const path = require('path');
const TI = require('./threatintel');
const VM = require('./vendor-mirror');

const ROOT = path.join(__dirname, '..');
const FINDINGS = () => process.env.FINDINGS_JSONL || path.join(ROOT, 'reports', 'findings.jsonl');
const WATCHLIST = path.join(ROOT, 'reports', 'ti-watchlist.txt');

function cvesFromFindings() {
  const out = new Set();
  let text = '';
  try { text = fs.readFileSync(FINDINGS(), 'utf8'); } catch {}
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const f = JSON.parse(line);
      for (const c of Array.isArray(f.cves) ? f.cves : []) out.add(c);
    } catch {}
  }
  return [...out];
}

function cvesFromWatchlist() {
  let text = '';
  try { text = fs.readFileSync(WATCHLIST, 'utf8'); } catch {}
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

function reposFromManifest() {
  const seen = new Map();
  for (const e of VM.readManifest()) {
    if (!e.owner || !e.repo || !e.instance) continue;
    const slug = e.owner + '/' + e.repo;
    if (!seen.has(slug)) seen.set(slug, e.instance);
  }
  for (const slug of VM.POC_REPOS) {
    const [owner, repo] = slug.split('/');
    if (!seen.has(slug)) seen.set(slug, VM.DEFAULT_INSTANCE);
  }
  return [...seen].map(([slug, instance]) => ({ slug, instance }));
}

async function main() {
  const argv = process.argv.slice(2);
  const startedAt = new Date().toISOString();
  const report = { started_at: startedAt };

  // 1) threatintel refresh (KEV always + CVEs from findings/watchlist)
  try {
    const kev = await TI.refreshKevCatalog({});
    const cves = [...new Set([...cvesFromFindings(), ...cvesFromWatchlist()])];
    const results = cves.length ? await TI.refreshAll(cves, { delayMs: 1500 }) : [];
    report.threatintel = {
      ok: true,
      kev_catalog: kev,
      refreshed_cves: results.map((r) => ({ cve: r.cve, nvd: !!r.nvd, epss: !!r.epss, kev: r.kev ? true : false })),
    };
  } catch (e) {
    report.threatintel = { ok: false, error: e.message };
  }

  // 2) vendor mirror: re-pull pinned repos, verify hashes, rebuild the PoC index
  if (!argv.includes('--skip-vendor')) {
    try {
      const pulls = [];
      for (const { slug, instance } of reposFromManifest()) {
        const r = await VM.pull({}, slug, { instance });
        pulls.push({ repo: slug, sha: r.sha || null, cached: !!r.cached, ok: !!r.ok, error: r.error });
      }
      const verify = VM.verify();
      const index = VM.indexPoc({});
      report.vendor_mirror = { ok: verify.ok, pulls, verified: verify.checked, hash_ok: verify.ok, poc_index: index };
    } catch (e) {
      report.vendor_mirror = { ok: false, error: e.message };
    }
  }

  // 3) knowledge base index rebuild
  if (!argv.includes('--skip-kb')) {
    try {
      const KB = require('./kb-search');
      report.kb_index = KB.index({ includeReports: true });
    } catch (e) {
      report.kb_index = { ok: false, error: e.message };
    }
  }

  report.finished_at = new Date().toISOString();
  console.log(JSON.stringify(report));
  // exit non-zero only if EVERYTHING failed — partial success still keeps the cache warm
  const allFailed = [report.threatintel, report.vendor_mirror, report.kb_index]
    .filter(Boolean)
    .every((r) => r.ok === false);
  process.exit(allFailed ? 1 : 0);
}
main();
