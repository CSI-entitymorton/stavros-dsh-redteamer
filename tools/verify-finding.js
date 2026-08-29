#!/usr/bin/env node
// Oracle-verification: a finding is not PROVEN until its structured `verify` PoC re-fires N/N
// against the LIVE target through repeater's request engine. Ladder: inconclusive < confirmed
// (agent asserts) < verified (oracle re-fired N/N). Only findings carrying a `verify` block
// auto-verify (no prose parsing).
//
// Ondata1 A1/A2 bridge: when record-finding.recordWithVerify() drives this verifier, BOTH
// outcomes are receipted to disk as a mechanical oracle (artifacts/oracle/<token>.json,
// type 'http-diff', anchor = "outcome passed|failed: <reason>") and attached to the finding as
// f.oracle + f.evidence_quote — so reality-level rows always carry disk-backed machine evidence.
// verifyFile() batch mode is left untouched on purpose: in-place edits of chained lines break
// the A3 hash-chain by construction and record() will refuse appends until reconciled (visible,
// not silent).
//
// verify block (optional, in the finding JSON):
//   "verify": { "method":"GET", "url":"https://HOST/api/x", "as":"user_a", "data":null,
//               "expect": { "status":200, "body_contains":"marker",
//                           "body_similarity_to":null, "similarity_min":0.6 } }
const fs = require('fs');
const path = require('path');

const FINDINGS = () => process.env.FINDINGS_JSONL || path.join(__dirname, '..', 'reports', 'findings.jsonl');

// Check one response against an expect block. Returns { ok, reason }.
function checkExpect(res, expect, baselineBody) {
  if (res.error) return { ok: false, reason: 'request error: ' + res.error };
  if (res.timeout) return { ok: false, reason: 'timeout' };
  if (expect.status != null && res.status !== expect.status)
    return { ok: false, reason: `status ${res.status} !== ${expect.status}` };
  const body = res.body || '';
  if (expect.body_contains && !body.includes(expect.body_contains))
    return { ok: false, reason: `body missing "${expect.body_contains}"` };
  if (expect.body_similarity_to) {
    const { similarity } = require('./repeater');
    const min = expect.similarity_min != null ? expect.similarity_min : 0.6;
    const sim = similarity(baselineBody || '', body);
    if (sim < min) return { ok: false, reason: `similarity ${sim.toFixed(3)} < ${min}` };
  }
  return { ok: true, reason: 'ok' };
}

// Re-fire a finding's verify PoC `times` times. Passes only if ALL runs satisfy `expect`.
async function verifyOne(finding, { times = 2, exec } = {}) {
  const v = finding && finding.verify;
  if (!v || !v.url) return { verified: false, runs: [], reason: 'no verify block' };
  exec = exec || defaultExec;
  const expect = v.expect || {};
  let baselineBody = null;
  if (expect.body_similarity_to) {
    const b = await exec({ method: 'GET', url: expect.body_similarity_to, as: v.as, data: null });
    baselineBody = b.body || '';
  }
  const runs = [];
  for (let i = 0; i < times; i++) {
    const res = await exec({ method: v.method || 'GET', url: v.url, data: v.data == null ? null : v.data, as: v.as });
    const c = checkExpect(res, expect, baselineBody);
    runs.push({ status: res.status, ok: c.ok, reason: c.reason });
    if (!c.ok) return { verified: false, runs, reason: `run ${i + 1}/${times} failed: ${c.reason}` };
  }
  return { verified: true, runs, reason: `${times}/${times} passed` };
}

// Default exec: reuse repeater's request engine (scope guard + DNS pin + identity headers).
async function defaultExec({ method, url, data, as }) {
  const { loadScope } = require('./scope-guard');
  const rep = require('./repeater');
  const scope = loadScope();
  const idHeaders = await rep.resolveIdentity(as);
  const headerMap = {};
  const hdrList = ['User-Agent: ' + rep.DEFAULT_UA, ...idHeaders, 'Accept-Encoding: identity'];
  // JSON bodies need an explicit content type or ASP.NET-style APIs answer 415
  if (data != null && !hdrList.some((h) => h.toLowerCase().startsWith('content-type:'))) {
    hdrList.push('Content-Type: application/json');
  }
  for (const h of hdrList) {
    const i = h.indexOf(':');
    if (i > 0) headerMap[h.slice(0, i).trim()] = h.slice(i + 1).trim();
  }
  const headersFor = () => Object.assign({}, headerMap);
  const res = await rep.sendChain(url, method || 'GET', headersFor, data == null ? null : data,
    { timeout: 10000, showBody: true, follow: false }, scope);
  if (res.blocked) return { error: 'scope-blocked: ' + res.reason };
  return res; // { status, body, headers, ... }
}

// Batch: re-verify every finding with a `verify` block not yet verified; update in place.
async function verifyFile(file, { exec } = {}) {
  file = file || FINDINGS();
  if (!fs.existsSync(file)) return { updated: 0, checked: 0, reason: 'no findings file' };
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  let updated = 0, checked = 0;
  const out = [];
  for (const line of lines) {
    let f;
    try { f = JSON.parse(line); } catch { out.push(line); continue; }
    if (f.verify && f.status !== 'verified') {
      checked++;
      const r = await verifyOne(f, { exec });
      if (r.verified) { f.status = 'verified'; f.verified = true; f.verified_at = new Date().toISOString(); updated++; }
      else { f.verify_failed = true; f.verify_reason = r.reason; }
      out.push(JSON.stringify(f));
    } else out.push(line);
  }
  const tmp = file + '.' + process.pid;
  fs.writeFileSync(tmp, out.join('\n') + '\n');
  fs.renameSync(tmp, file);
  return { updated, checked };
}

module.exports = { verifyOne, verifyFile, checkExpect, FINDINGS };

if (require.main === module) {
  (async () => {
    const [cmd, arg] = process.argv.slice(2);
    if (cmd === 'one') {
      console.log(JSON.stringify(await verifyOne(JSON.parse(arg)), null, 2));
    } else if (cmd === 'batch') {
      const fi = process.argv.indexOf('--file');
      console.log(JSON.stringify(await verifyFile(fi >= 0 ? process.argv[fi + 1] : undefined), null, 2));
    } else {
      console.error("usage: node verify-finding.js one '<finding-json>' | batch [--file findings.jsonl]");
      process.exit(2);
    }
  })();
}
