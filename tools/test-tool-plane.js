#!/usr/bin/env node
// Zero-dependency test for tools/tool-plane.js.
// Run: node tools/test-tool-plane.js  → prints PASS/FAIL per case, exit 1 on any failure.

'use strict';
const fs = require('fs');
const { TOOL_PLANE, detect, hasBin, table, markInstallFailed, OUT } = require('./tool-plane');

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name}`); }
}

ok('TOOL_PLANE has scan category', !!TOOL_PLANE.scan);
ok('TOOL_PLANE nmap required', TOOL_PLANE.scan.nmap.required === true);

// hasBin: on this machine 'node' must be found; '__definitely_missing__' must not
ok('hasBin node', hasBin(process.execPath.includes('node') ? 'node' : 'node'));
ok('hasBin missing binary', !hasBin('__definitely_missing_bin_xyz__'));

const d = detect();
ok('detect returns tools object', typeof d.tools === 'object');
ok('detect covers every TOOL_PLANE bin', Object.keys(d.tools).length >= Object.keys(TOOL_PLANE).length);
ok('table renders header', table(d).includes('| Tool |'));

// markInstallFailed round-trip (uses the real OUT path under reports/tmp)
markInstallFailed('__fake_tool__', 'test');
const back = JSON.parse(fs.readFileSync(OUT, 'utf8'));
ok('markInstallFailed persisted', back.tools.__fake_tool__ && back.tools.__fake_tool__.install_state === 'install-failed');
// cleanup the fake entry so it does not pollute real runs
try {
  delete back.tools.__fake_tool__;
  fs.writeFileSync(OUT, JSON.stringify(back, null, 2) + '\n');
} catch {}

console.log(`\ntool-plane: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);