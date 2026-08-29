#!/usr/bin/env node
// Evidence = exact quote (ondata1 A2 / PentestGPT P3): for findings that claim reality the
// `evidence_quote` field is REQUIRED and its text must be a byte-per-byte substring of a
// workspace artifact. Model paraphrases/summaries go to f.diagnostics (free-form, documented
// as NON-evidence — never used by any check).
//
//   evidence_quote: { file: '<workspace-relative artifact path>', text: '<exact quote>' }
//
// Rejections (fail-closed): missing quote on reality claims, file outside workspace, '..'
// traversal, symlink escape, unreadable/oversized file, text not found verbatim.
// Exported validateQuote(f, opts) is reused by record-finding.js and gate.js.
'use strict';
const fs = require('fs');
const path = require('path');
const { claimingReality, safeResolveWithin, WS_ROOT } = require('./oracle');

const MAX_QUOTE_BYTES = 64 * 1024;  // sanity cap on the quoted text
const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024; // refuse to scan absurd artifacts

// Validate f.evidence_quote against DISK right now. Returns null when acceptable, else a
// specific rejection reason. Required when the finding claims reality; optional-but-validated
// elsewhere (a broken quote never rides along silently).
function validateQuote(f, opts) {
  const ws = (opts && opts.wsRoot) || WS_ROOT();
  if (!f || typeof f !== 'object') return 'finding is not an object';
  const q = f.evidence_quote;
  if (q == null || q === '') {
    if (claimingReality(f))
      return 'evidence_quote {file,text} required: reality claims (status confirmed/verified or verify_level exploited/proven_impact) must quote an exact slice of a workspace artifact (model summaries belong in f.diagnostics and are NOT evidence)';
    return null;
  }
  if (typeof q !== 'object' || Array.isArray(q))
    return 'evidence_quote must be an object {file,text}';
  if (typeof q.file !== 'string' || q.file.trim() === '') return 'evidence_quote.file is empty';
  if (typeof q.text !== 'string' || q.text === '') return 'evidence_quote.text is empty';
  if (!Buffer.byteLength(q.text, 'utf8')) return 'evidence_quote.text is empty';
  if (Buffer.byteLength(q.text, 'utf8') > MAX_QUOTE_BYTES)
    return `evidence_quote.text too large (>${MAX_QUOTE_BYTES} bytes) — quote a minimal exact slice`;
  const rs = safeResolveWithin(q.file, ws);
  if (rs.error) return `evidence_quote.file: ${rs.error}`;
  let buf;
  try {
    if (fs.statSync(rs.full).size > MAX_ARTIFACT_BYTES)
      return `evidence_quote.file larger than ${MAX_ARTIFACT_BYTES} bytes — quote a smaller artifact`;
    buf = fs.readFileSync(rs.full);
  } catch (e) {
    return `evidence_quote.file unreadable: ${e.message}`;
  }
  // Byte-per-byte match: Buffer.indexOf compares raw utf8 bytes, immune to normalization.
  if (buf.indexOf(Buffer.from(q.text, 'utf8')) < 0)
    return 'evidence_quote.text is NOT a verbatim substring of the artifact (paraphrase rejected)';
  return null;
}

module.exports = { validateQuote, MAX_QUOTE_BYTES, MAX_ARTIFACT_BYTES };
