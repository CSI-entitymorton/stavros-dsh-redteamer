#!/usr/bin/env node
// searchsploit (Exploit-DB) lookup wrapper — normalized, zero-dep. Queries the LOCAL
// exploit-db (no network I/O: searchsploit reads /usr/share/exploitdb), so it needs no
// scope-guard. Output is normalized JSON that the reporter (report-html.js) can fold into
// the final report. Second local source: the hash-pinned PoC archives mirrored under
// vendor/mirror/ (indexed by tools/vendor-mirror.js into vendor/poc-archive/index.json) —
// matched by CVE id or path substring, returned as `poc_archive` entries pointing INTO the
// sealed zip (never extracted or executed by this harness; open in an isolated lab only).
//   node tools/searchsploit.js <term>            # CVE-2021-44228 | apache 2.4 | service name
//   node tools/searchsploit.js <term> --jsonl reports/searchsploit.jsonl   # append records
//
// ponytail: depends on searchsploit's --json schema; the executable ships with Kali's
// exploitdb package. If it's absent the wrapper fails closed with a clear error.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function writeAtomic(file, data) {
  const tmp = file + '.' + process.pid;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

// Normalize one RESULTS_EXPLOIT / RESULTS_SHELLCODE entry. Splits the semicolon-joined
// "Codes" field into CVE ids (cves) and non-CVE references (codes, e.g. MS17-010).
function normalizeEntry(e, kind) {
  e = e || {};
  const codes = String(e.Codes || '')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
  return {
    title: e.Title || null,
    edb_id: e['EDB-ID'] || null,
    date: e.Date_Published || null,
    author: e.Author || null,
    type: e.Type || null,
    platform: e.Platform || null,
    port: e.Port || null,
    verified: e.Verified === '1',
    kind: kind || (e.Source ? 'exploit' : 'shellcode'),
    cves: codes.filter((c) => /^CVE-\d{4}-\d+/i.test(c)).map((c) => c.toUpperCase()),
    codes: codes.filter((c) => !/^CVE-\d{4}-\d+/i.test(c)),
    path: e.Path || null,
    source: e.Source || null,
  };
}

// Pure parser: searchsploit --json text -> { term, exploits[], shellcode[] }. Malformed
// input returns an empty result instead of throwing.
function parseSearchsploit(text) {
  const out = { term: null, exploits: [], shellcode: [] };
  let j;
  try {
    j = JSON.parse(String(text));
  } catch {
    return out;
  }
  if (!j || typeof j !== 'object') return out;
  out.term = j.SEARCH || null;
  for (const e of Array.isArray(j.RESULTS_EXPLOIT) ? j.RESULTS_EXPLOIT : [])
    out.exploits.push(normalizeEntry(e, 'exploit'));
  for (const e of Array.isArray(j.RESULTS_SHELLCODE) ? j.RESULTS_SHELLCODE : [])
    out.shellcode.push(normalizeEntry(e, 'shellcode'));
  return out;
}

function defaultExec(term) {
  const r = spawnSync('searchsploit', ['--json', String(term)], { encoding: 'utf8' });
  return { stdout: (r.stdout || '') + (r.stderr || ''), status: r.status == null ? 1 : r.status, error: r.error && r.error.message };
}

// Run a lookup. ctx.exec is injectable for offline tests; ctx.pocIndexFile overrides the
// vendor PoC-archive index (injectable for tests too).
function lookup(term, ctx) {
  ctx = ctx || {};
  const exec = ctx.exec || defaultExec;
  const t = String(term == null ? '' : term).trim();
  if (!t) return { ok: false, error: 'no search term' };
  const res = exec(t);
  if (res.status !== 0) return { ok: false, error: res.error || ('searchsploit failed (exit ' + res.status + ')') };
  const parsed = parseSearchsploit(res.stdout);
  // second local source: hash-pinned PoC archives (vendor/poc-archive/index.json). Best-effort:
  // a missing index simply yields an empty list, never a failure.
  let poc_archive = [];
  try {
    const vm = require('./vendor-mirror');
    poc_archive = vm.queryPocIndex(t, ctx.pocIndexFile);
  } catch {}
  return { ok: true, term: t, ...parsed, poc_archive, count: parsed.exploits.length + parsed.shellcode.length };
}

function main() {
  const argv = process.argv.slice(2);
  const jsonlIdx = argv.indexOf('--jsonl');
  const jsonlFile = jsonlIdx >= 0 ? argv[jsonlIdx + 1] : null;
  const term = argv.find((a, i) => a !== '--jsonl' && (jsonlIdx < 0 || i !== jsonlIdx + 1));
  if (!term) {
    console.error('usage: node tools/searchsploit.js <term> [--jsonl <outfile>]');
    process.exit(2);
  }
  const res = lookup(term);
  if (!res.ok) {
    console.error(JSON.stringify(res));
    process.exit(1);
  }
  if (jsonlFile) {
    const dir = path.dirname(jsonlFile);
    if (dir) fs.mkdirSync(dir, { recursive: true });
    const rows = [...res.exploits, ...res.shellcode].map((r) =>
      JSON.stringify({ ts: new Date().toISOString(), term: res.term, ...r }));
    let existing = '';
    try { existing = fs.readFileSync(jsonlFile, 'utf8'); } catch {}
    writeAtomic(jsonlFile, existing + (rows.length ? rows.join('\n') + '\n' : ''));
  }
  console.log(JSON.stringify(res, null, 2));
}

if (require.main === module) main();

module.exports = { parseSearchsploit, lookup, normalizeEntry };
