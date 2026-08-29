#!/usr/bin/env node
// Mechanical oracle for findings (ondata1 A1 / OSS-gap G1): a finding that CLAIMS reality
// (status confirmed|verified, or verify_level exploited|proven_impact) must carry a valid
// `oracle` field backed by a machine-generated artifact on disk — no LLM self-attestation.
//
//   oracle: { type: 'oob'|'http-diff'|'console'|'script', ref: '<path>[#<line>]', token: '<string>' }
//
// Valid refs (fail-closed validation below):
//   (a) one line of the append-only log reports/tmp/oracle-log.jsonl written by THIS tool;
//   (b) a JSON file under <ws>/artifacts/oracle/ whose raw content contains the token verbatim;
//   (c) for type 'oob': the OOB markers/hits jsonl written by tools/oob.js (READ-ONLY consumption).
// Refs outside the workspace, with '..' segments, missing tokens, type mismatches or invalid
// JSON artifacts are REJECTED with a specific reason. Hypothesis levels (status 'inconclusive',
// verify_level 'suspected'|'triggered') do not need an oracle — see record-finding.js.
//
// CLI:
//   node tools/oracle.js record '{"type":"http-diff","token":"ab12..","note":"...","data":{}}'
//       -> appends {ts,type,token,...} to the oracle log and prints {"ok":true,"ref":"...#N"}
//   node tools/oracle.js check  '<finding-json>'   -> validate f.oracle against disk (exit 0/1)
//   node tools/oracle.js receipt '{"type":"http-diff","anchor":"...","data":{}}'
//       -> write a JSON receipt under artifacts/oracle/ and print its ref (used by record-finding)
//
// Env overrides (offline tests): DSH_WS_ROOT, ORACLE_LOG, ORACLE_ARTIFACTS, OOB_MARKERS, OOB_HITS.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TYPES = ['oob', 'http-diff', 'console', 'script'];
const GENESIS = '0'.repeat(64); // prev_sha256 of the first chained finding line
const TOKEN_RE = /^[\x21-\x7E]{8,256}$/; // printable non-space ASCII, 8..256 chars

const WS_ROOT = () => process.env.DSH_WS_ROOT || path.join(__dirname, '..');
const ORACLE_LOG_REL = 'reports/tmp/oracle-log.jsonl';
const ORACLE_LOG = () => process.env.ORACLE_LOG || path.join(WS_ROOT(), ORACLE_LOG_REL);
const ARTIFACTS_DIR = () => process.env.ORACLE_ARTIFACTS || path.join(WS_ROOT(), 'artifacts', 'oracle');
// OOB files written by tools/oob.js — consumed strictly READ-ONLY here.
const OOB_MARKERS = () => process.env.OOB_MARKERS || path.join(WS_ROOT(), 'reports', 'oob', 'markers.jsonl');
const OOB_HITS = () => process.env.OOB_HITS || path.join(WS_ROOT(), 'reports', 'oob', 'hits.jsonl');

// True when the finding claims reality (needs oracle + evidence quote). Kept in sync with the
// record-finding.js taxonomy; exported so gate.js and tests share ONE definition.
function claimingReality(f) {
  if (!f || typeof f !== 'object') return false;
  return f.status === 'confirmed' || f.status === 'verified' ||
    f.verify_level === 'exploited' || f.verify_level === 'proven_impact';
}

// Resolve `rel` inside wsRoot, refusing absolute paths, '..' traversal, NUL/backslashes and
// symlink escapes (realpath containment). Returns { full } or { error }.
function safeResolveWithin(rel, wsRoot) {
  if (typeof rel !== 'string' || rel.trim() === '') return { error: 'ref is empty' };
  if (rel.includes('\0')) return { error: 'ref contains NUL byte' };
  if (rel.includes('\\')) return { error: 'ref must use "/" separators' };
  if (path.isAbsolute(rel)) return { error: 'ref must be workspace-relative (got absolute path)' };
  const norm = path.normalize(rel);
  if (norm.split('/').includes('..')) return { error: `ref path traversal rejected: ${rel}` };
  let rootReal, st, full;
  try {
    full = path.resolve(wsRoot, norm);
    st = fs.statSync(full);
    if (!st.isFile()) return { error: `ref is not a regular file: ${rel}` };
    rootReal = fs.realpathSync(wsRoot);
    const real = fs.realpathSync(full);
    if (real !== rootReal && !real.startsWith(rootReal + path.sep))
      return { error: 'ref resolves outside the workspace (symlink escape)' };
  } catch (e) {
    return { error: `ref unreadable (${e.code || e.message}): ${rel}` };
  }
  return { full };
}

function sameFile(a, b) {
  try { return fs.realpathSync(a) === fs.realpathSync(b); } catch { return false; }
}

function withinDir(full, dir) {
  const r = path.relative(dir, full);
  return r === '' || (!r.startsWith('..') && !path.isAbsolute(r));
}

// Classify a resolved ref into 'log' | 'artifact' | 'oob' | null.
function classifyRef(full) {
  if (sameFile(full, ORACLE_LOG())) return 'log';
  if (withinDir(full, ARTIFACTS_DIR())) return 'artifact';
  if (sameFile(full, OOB_MARKERS()) || sameFile(full, OOB_HITS())) return 'oob';
  return null;
}

// ref syntax: "<workspace-relative path>" optionally suffixed "#<lineNumber>" (jsonl only).
function parseRef(ref) {
  const i = ref.lastIndexOf('#');
  if (i > 0 && /^\d+$/.test(ref.slice(i + 1))) {
    return { p: ref.slice(0, i), line: parseInt(ref.slice(i + 1), 10) };
  }
  return { p: ref, line: null };
}

function tryParseJson(s) {
  try { return { v: JSON.parse(s) }; } catch (e) { return { err: e.message }; }
}

// Validate a finding's `oracle` object against DISK right now. Returns null when valid,
// otherwise a specific rejection reason. opts.wsRoot overrides the workspace root (tests).
function validateOracle(o, opts) {
  const ws = (opts && opts.wsRoot) || WS_ROOT();
  if (!o || typeof o !== 'object' || Array.isArray(o))
    return 'oracle must be an object {type,ref,token}';
  const { type, ref, token } = o;
  if (typeof type !== 'string' || !TYPES.includes(type))
    return `oracle.type must be one of ${TYPES.join('|')} (got ${JSON.stringify(type)})`;
  if (typeof token !== 'string' || !TOKEN_RE.test(token))
    return 'oracle.token must be a printable ASCII string of 8..256 chars';
  if (typeof ref !== 'string' || ref.trim() === '') return 'oracle.ref is empty';
  const pr = parseRef(ref);
  const rs = safeResolveWithin(pr.p, ws);
  if (rs.error) return `oracle.ref: ${rs.error}`;
  const kind = classifyRef(rs.full);
  if (kind === 'log') return validateLogRef(rs.full, pr.line, type, token);
  if (kind === 'artifact') return validateArtifactRef(rs.full, pr.line, type, token);
  if (kind === 'oob') return validateOobRef(rs.full, pr.line, type, token);
  return 'oracle.ref must point to the oracle log (reports/tmp/oracle-log.jsonl), a JSON file under artifacts/oracle/, or the OOB markers/hits jsonl written by tools/oob.js';
}

function validateLogRef(full, lineNo, type, token) {
  let lines;
  try { lines = fs.readFileSync(full, 'utf8').split('\n'); } catch (e) {
    return `oracle-log unreadable: ${e.message}`;
  }
  const checkLine = (raw, idx) => {
    if (!raw.trim()) return `oracle-log line ${idx + 1} is empty`;
    if (!raw.includes(token)) return `token not found verbatim in oracle-log line ${idx + 1}`;
    const parsed = tryParseJson(raw);
    if (parsed.err) return `corrupt oracle-log line ${idx + 1} (invalid JSON): ${parsed.err}`;
    if (parsed.v.type !== type)
      return `oracle.type "${type}" does not match logged type "${parsed.v.type}" (line ${idx + 1})`;
    return null;
  };
  if (lineNo != null) {
    const raw = lineNo >= 1 && lineNo <= lines.length ? lines[lineNo - 1] : null;
    if (raw == null) return `oracle-log line ${lineNo} not found (log has ${lines.filter((l) => l.trim()).length} lines)`;
    return checkLine(raw, lineNo - 1);
  }
  let sawTokenWrongType = null;
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes(token)) continue;
    const err = checkLine(lines[i], i);
    if (!err) return null;
    sawTokenWrongType = sawTokenWrongType || err;
  }
  return sawTokenWrongType || `no oracle-log line contains token "${token.slice(0, 4)}…"`;
}

function validateArtifactRef(full, lineNo, type, token) {
  if (lineNo != null) return 'line refs (#N) apply only to jsonl logs, not artifact files';
  let raw;
  try { raw = fs.readFileSync(full, 'utf8'); } catch (e) { return `artifact unreadable: ${e.message}`; }
  const parsed = tryParseJson(raw);
  if (parsed.err) return `artifact JSON invalid: ${parsed.err}`;
  if (!raw.includes(token)) return 'token not found verbatim in artifact content';
  if (typeof parsed.v.type === 'string' && parsed.v.type !== type)
    return `oracle.type "${type}" does not match artifact type "${parsed.v.type}"`;
  return null;
}

function validateOobRef(full, lineNo, type, token) {
  // OOB markers/hits are accepted ONLY for type 'oob' — never as cover for other oracle types.
  if (type !== 'oob')
    return `oracle.type mismatch: an OOB markers/hits ref requires type "oob" (got "${type}")`;
  let text;
  try { text = fs.readFileSync(full, 'utf8'); } catch (e) { return `OOB file unreadable: ${e.message}`; }
  if (lineNo != null) {
    const lines = text.split('\n');
    const raw = lineNo >= 1 && lineNo <= lines.length ? lines[lineNo - 1] : '';
    if (!raw.includes(token)) return `token not found verbatim in OOB file line ${lineNo}`;
    return null;
  }
  if (!text.includes(token)) return 'token not found verbatim in OOB markers/hits file';
  return null;
}

// Workspace-relative posix path for a file (null when outside WS_ROOT → fail closed).
function relFromWs(full) {
  const r = path.relative(WS_ROOT(), full);
  if (!r || r.startsWith('..') || path.isAbsolute(r)) return null;
  return r.split(path.sep).join('/');
}

// Append one machine-generated event to the append-only oracle log.
// Returns { ok:true, ref:'<log-rel>#N' } or { ok:false, error }.
function recordEvent(ev) {
  const type = ev && ev.type;
  if (!TYPES.includes(type)) return { ok: false, error: `type must be one of ${TYPES.join('|')}` };
  const token = ev.token;
  if (typeof token !== 'string' || !TOKEN_RE.test(token))
    return { ok: false, error: 'token must be a printable ASCII string of 8..256 chars' };
  if (ev.note != null && typeof ev.note !== 'string') return { ok: false, error: 'note must be a string' };
  if (ev.data != null && (typeof ev.data !== 'object' || Array.isArray(ev.data)))
    return { ok: false, error: 'data must be a JSON object' };
  let line;
  try {
    line = JSON.stringify({ ts: new Date().toISOString(), type, token,
      ...(ev.note ? { note: ev.note } : {}), ...(ev.data ? { data: ev.data } : {}) });
  } catch (e) { return { ok: false, error: 'event not serializable: ' + e.message }; }
  const log = ORACLE_LOG();
  try { fs.mkdirSync(path.dirname(log), { recursive: true }); } catch (e) {
    return { ok: false, error: 'cannot create oracle log dir: ' + e.message };
  }
  let n;
  try {
    n = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).length : 0;
    fs.appendFileSync(log, line + '\n');
  } catch (e) { return { ok: false, error: 'append failed: ' + e.message }; }
  const rel = relFromWs(log);
  if (!rel) return { ok: false, error: 'ORACLE_LOG lives outside DSH_WS_ROOT — refusing (fail-closed)' };
  return { ok: true, ref: `${rel}#${n + 1}`, token, type };
}

// Write a JSON receipt artifact under artifacts/oracle/ (machine evidence for verify re-fires
// and scripted checks). The anchor string is embedded verbatim so callers can quote it exactly.
function writeReceipt({ type, anchor, data }) {
  if (!TYPES.includes(type)) return { ok: false, error: `type must be one of ${TYPES.join('|')}` };
  if (typeof anchor !== 'string' || !anchor.trim()) return { ok: false, error: 'anchor must be a non-empty string' };
  if (data != null && (typeof data !== 'object' || Array.isArray(data)))
    return { ok: false, error: 'data must be a JSON object' };
  const token = crypto.randomBytes(8).toString('hex');
  const dir = ARTIFACTS_DIR();
  try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {
    return { ok: false, error: 'cannot create artifacts dir: ' + e.message };
  }
  let body;
  try {
    body = JSON.stringify({ kind: 'oracle-receipt', ts: new Date().toISOString(), type, token, anchor, ...(data || {}) }, null, 2) + '\n';
  } catch (e) { return { ok: false, error: 'receipt not serializable: ' + e.message }; }
  const file = path.join(dir, token + '.json');
  try { fs.writeFileSync(file, body); } catch (e) { return { ok: false, error: 'write failed: ' + e.message }; }
  const rel = relFromWs(file);
  if (!rel) return { ok: false, error: 'ORACLE_ARTIFACTS lives outside DSH_WS_ROOT — refusing (fail-closed)' };
  return { ok: true, ref: rel, token, anchor, file };
}

// ─── CLI ───

function main() {
  const [cmd, arg] = process.argv.slice(2);
  if (cmd === 'record') {
    let ev;
    try { ev = JSON.parse(arg || ''); } catch (e) {
      console.log(JSON.stringify({ ok: false, error: 'invalid JSON argument: ' + e.message }));
      process.exit(1);
    }
    const r = recordEvent(ev);
    console.log(JSON.stringify(r));
    process.exit(r.ok ? 0 : 1);
  }
  if (cmd === 'check') {
    let f;
    try { f = JSON.parse(arg || ''); } catch (e) {
      console.log(JSON.stringify({ ok: false, error: 'invalid finding JSON: ' + e.message }));
      process.exit(1);
    }
    if (!f.oracle) {
      console.log(JSON.stringify({ ok: false, error: 'finding has no oracle field (required for reality claims: status confirmed/verified or verify_level exploited/proven_impact; hypothesis levels exempt)' }));
      process.exit(1);
    }
    const err = validateOracle(f.oracle);
    if (err) { console.log(JSON.stringify({ ok: false, error: err })); process.exit(1); }
    console.log(JSON.stringify({ ok: true, type: f.oracle.type, ref: f.oracle.ref }));
    process.exit(0);
  }
  if (cmd === 'receipt') {
    let spec;
    try { spec = JSON.parse(arg || ''); } catch (e) {
      console.log(JSON.stringify({ ok: false, error: 'invalid JSON argument: ' + e.message }));
      process.exit(1);
    }
    const r = writeReceipt(spec);
    console.log(JSON.stringify(r));
    process.exit(r.ok ? 0 : 1);
  }
  console.error('usage: node tools/oracle.js record \'<json>\' | check \'<finding-json>\' | receipt \'<json>\'');
  console.error('types: ' + TYPES.join('|'));
  process.exit(2);
}

if (require.main === module) main();
module.exports = {
  TYPES, GENESIS, TOKEN_RE, claimingReality, validateOracle, parseRef,
  safeResolveWithin, classifyRef, recordEvent, writeReceipt,
  WS_ROOT, ORACLE_LOG, ARTIFACTS_DIR, OOB_MARKERS, OOB_HITS,
};
