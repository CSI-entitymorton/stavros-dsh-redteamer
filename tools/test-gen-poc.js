#!/usr/bin/env node
// Zero-dependency test for tools/gen-poc.js.
// Run: node tools/test-gen-poc.js  → prints PASS/FAIL per case, exit 1 on any failure.

'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { findingId, pickFinding, genPython } = require('./gen-poc');

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name}`); }
}

const sample = {
  id: 'SAMPLE-1',
  host: '127.0.0.1',
  endpoint: '/api/x',
  title: 'SQLi in search',
  severity: 'High',
  poc: 'GET /api/x?id=1%27 HTTP/1.1',
};

ok('findingId deterministic', findingId(sample) === 'sample-1');
const py = genPython(sample);
ok('genPython returns string', typeof py === 'string');
ok('genPython has --target arg', py.includes("'-u'") && py.includes("'--target'"));
ok('genPython never hardcodes target in request', !py.includes('http://127.0.0.1'));
ok('genPython exit 0 = reproduced', py.includes('sys.exit(0)'));
ok('genPython dangerous disabled by default', py.includes('--dangerous'));

// pickFinding with no real data: returns null for unknown
ok('pickFinding unknown returns null', pickFinding('__none__') === null);

// genPython produces valid python syntax (best-effort: starts with shebang + has main)
ok('genPython has main()', py.includes('def main():'));

console.log(`\ngen-poc: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);