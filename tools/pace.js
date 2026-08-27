#!/usr/bin/env node
// Global cross-process rate limiter.
// Every network tool (repeater.js, cors.js, graphql.js, dom-check.js, oob.js clients, ...)
// calls pace.wait(rps) before each request. State lives in a file (tools/.pace.json), so
// the limit holds even when several agents/processes run in parallel — scope.json's
// max_requests_per_second becomes a true global ceiling instead of a per-process one.
//
// Best-effort: two processes can still race the file write; that's acceptable. If the
// state file is deleted the limiter resets (last=0).
const fs = require('fs');
const path = require('path');

const PACE_FILE = path.join(__dirname, '.pace.json');

function load() {
  try {
    return JSON.parse(fs.readFileSync(PACE_FILE, 'utf8'));
  } catch {
    return { last: 0 };
  }
}

// Sync sleep without deps (works in the main thread in Node).
function sleep(ms) {
  if (ms <= 0) return;
  const sab = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(sab, 0, 0, ms);
}

// Wait so that the global inter-request gap (1000/rps) is respected. Returns ms waited.
function wait(rps, opts) {
  const o = opts || {};
  const gap = Math.max(1000 / Math.max(0.1, rps || 2), o.minGap || 0);
  const state = load();
  const now = Date.now();
  const next = Math.max(state.last + gap, now);
  const waitMs = Math.max(0, next - now);
  // Atomically-ish persist: write temp + rename so readers never see a half-written file.
  const tmp = PACE_FILE + '.' + process.pid;
  try {
    fs.writeFileSync(tmp, JSON.stringify({ last: next }));
    fs.renameSync(tmp, PACE_FILE);
  } catch {}
  if (waitMs > 0) sleep(waitMs);
  return waitMs;
}

module.exports = { wait, PACE_FILE };
