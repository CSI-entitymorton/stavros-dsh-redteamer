#!/usr/bin/env node
// Privacy tokenization at tool boundaries: free hosted models never see DISCOVERED PII
// (internal IPs, emails, secrets/hashes). Typed deterministic placeholders HOST_/IP_/EMAIL_/SECRET_.
// tokenize is gated by STAVROS_PRIVACY=1 (default off -> no-op). rehydrate is always active
// (local report-time restore is authorized). Map persists at reports/tmp/token-map.json (gitignored).
//
// ponytail: detection is seed(scope)+regex, best-effort, fail-OPEN on the unrecognized (spec limit).
// Placeholder counter is padStart(3) -> up to 999 per type; widen if a run exceeds it.
const fs = require('fs');
const path = require('path');

const MAP_FILE = () => process.env.TOKEN_MAP || path.join(__dirname, '..', 'reports', 'tmp', 'token-map.json');
const ENABLED = () => process.env.STAVROS_PRIVACY === '1';

function loadMap() {
  try { return JSON.parse(fs.readFileSync(MAP_FILE(), 'utf8')); } catch { return { forward: {}, counters: {} }; }
}
function saveMap(m) {
  const f = MAP_FILE();
  fs.mkdirSync(path.dirname(f), { recursive: true });
  const tmp = f + '.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(m, null, 2));
  fs.renameSync(tmp, f);
}

function tokenFor(real, type, m) {
  if (m.forward[real]) return m.forward[real];
  m.counters[type] = (m.counters[type] || 0) + 1;
  const tok = `${type}_${String(m.counters[type]).padStart(3, '0')}`;
  m.forward[real] = tok;
  return tok;
}

// Detection patterns -> placeholder type. JWT/known-keys and email BEFORE the broad IP pattern.
const PATTERNS = [
  ['SECRET', /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?/g], // JWT
  ['SECRET', /\b(?:sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35})\b/g],
  ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ['IP', /\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
];

// Populate HOST/IP tokens from scope so hostnames (not covered by regex) are recognized.
function seedFromScope(scope) {
  if (!ENABLED()) return loadMap();
  const m = loadMap();
  for (const h of scope.allowed_hosts || []) tokenFor(String(h).toLowerCase(), 'HOST', m);
  for (const ip of scope.allowed_ips || []) if (!String(ip).includes('/')) tokenFor(String(ip), 'IP', m);
  saveMap(m);
  return m;
}

function tokenize(text) {
  if (!ENABLED() || text == null) return text;
  let s = String(text);
  const m = loadMap();
  // 1) regex-detected values FIRST, so a seeded host substring (e.g. a domain) can't fragment
  // a longer match (e.g. an email) before the regex gets to see it whole.
  for (const [type, re] of PATTERNS) s = s.replace(re, (val) => tokenFor(val, type, m));
  // 2) already-known real values (longest first, so a domain isn't shadowed by a substring)
  for (const real of Object.keys(m.forward).sort((a, b) => b.length - a.length))
    s = s.split(real).join(m.forward[real]);
  saveMap(m);
  return s;
}

function rehydrate(text) {
  if (text == null) return text;
  const m = loadMap();
  const inverse = Object.entries(m.forward).map(([real, tok]) => [tok, real]).sort((a, b) => b[0].length - a[0].length);
  let s = String(text);
  for (const [tok, real] of inverse) s = s.split(tok).join(real);
  return s;
}

module.exports = { tokenize, rehydrate, seedFromScope, loadMap, MAP_FILE };
