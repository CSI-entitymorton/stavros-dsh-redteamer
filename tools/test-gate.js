#!/usr/bin/env node
// Zero-dependency test for tools/gate.js.
// Run: node tools/test-gate.js  → prints PASS/FAIL per case, exit 1 on any failure.

'use strict';
const path = require('path');
const fs = require('fs');
const os = require('os');
const { runGate, gateLogHasPass, checkFile, checkMarkers, checkFindings, checkVerify, checkNoPending, checkCoverage } = require('./gate');

// Hermetic workspace: gate.js resolves paths against GATE_WS (env override, default = package
// root). Point it at a mkdtemp fixture so the test never depends on the repo's live engagement
// files (scope.json / reports/ are gitignored and absent in a fresh checkout).
const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-ws-'));
fs.mkdirSync(path.join(ws, 'reports'), { recursive: true });
fs.writeFileSync(path.join(ws, 'scope.json'), JSON.stringify({ allowed_hosts: ['target.example'], allowed_ips: [] }));
fs.writeFileSync(path.join(ws, 'reports', 'findings.jsonl'), JSON.stringify({
  severity: 'Low', title: 'fixture', host: 'target.example', poc: 'x', status: 'inconclusive',
}) + '\n');
process.env.GATE_WS = ws;
process.env.GATE_LOG_FILE = path.join(ws, 'reports', 'gate-log.md');

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
ok('checkFindings min 1 passes (fixture has one finding)', findingsOne.ok);

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

fs.rmSync(ws, { recursive: true, force: true });
console.log(`\ngate: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);