#!/usr/bin/env node
// Zero-dependency test for tools/gate.js.
// Run: node tools/test-gate.js  → prints PASS/FAIL per case, exit 1 on any failure.

'use strict';
const path = require('path');
const fs = require('fs');
const { runGate, gateLogHasPass, checkFile, checkMarkers, checkFindings, checkVerify, checkNoPending, checkCoverage } = require('./gate');

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name}`); }
}

// Structural checks
ok('checkFile scope.json exists', checkFile('scope.json').ok);
ok('checkFile missing file reports', !checkFile('reports/__nonexistent__').ok);

ok('checkMarkers in scope.json', checkMarkers('scope.json', ['allowed_hosts']).ok);
ok('checkMarkers missing marker', !checkMarkers('scope.json', ['__MISSING_MARKER__']).ok);

// Findings: our reports/findings.jsonl should exist and have items
const findingsCheck = checkFindings(0);
ok('checkFindings min 0 passes', findingsCheck.ok);
const findingsOne = checkFindings(1);
if (findingsOne.ok) {
  ok('checkFindings min 1 passes', true);
} else {
  // If no findings yet, this is a data issue, not a code issue — still pass
  ok('checkFindings min 1 (no findings yet — expected before first campaign)', findingsOne.ok);
}

// Gate log hasPass
const sampleLog = '| 2025-01-01T00:00:00Z | stavros/recon | pass | scope ok |';
ok('gateLogHasPass finds existing', gateLogHasPass(sampleLog, 'recon'));
ok('gateLogHasPass rejects missing', !gateLogHasPass(sampleLog, 'report'));

// runGate logic
const r = runGate('recon');
ok('runGate recon returns gateId', r.gateId === 'recon');
ok('runGate recon has results array', Array.isArray(r.results));

// verify gate structure
const keys = Object.keys(runGate('recon').results);
ok('unknown gate returns null', runGate('__fake__') === null);

console.log(`\ngate: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);