// Self-check: epss.js offline lookups are deterministic, normalize input, and never
// fabricate a score for an unknown CVE/CWE.
// Run: node tools/test-epss.js
const assert = require('assert');
const E = require('./epss');

// normalization
assert.strictEqual(E.normCve('cve-2021-44228'), 'CVE-2021-44228');
assert.strictEqual(E.normCve('2021-44228'), 'CVE-2021-44228');
assert.strictEqual(E.normCwe('cwe-79'), 'CWE-79');
assert.strictEqual(E.normCwe('79'), 'CWE-79');

// known CVE -> embedded EPSS + percentile in range
const r = E.lookupEpss('CVE-2021-44228');
assert.ok(r, 'Log4Shell should be in the embedded map');
assert.strictEqual(r.source, 'embedded');
assert.ok(r.epss > 0 && r.epss <= 1, 'epss in (0,1]');
assert.ok(r.percentile > 0 && r.percentile <= 1, 'percentile in (0,1]');

// unknown CVE -> null (fail-open to "unknown", never 0.0)
assert.strictEqual(E.lookupEpss('CVE-9999-00000'), null);

// max across a list picks the highest EPSS
const max = E.lookupMaxEpss(['CVE-9999-00000', 'CVE-2023-44487', 'CVE-2017-0144']);
assert.strictEqual(max.cve, 'CVE-2017-0144');
assert.ok(max.epss > E.lookupEpss('CVE-2023-44487').epss);

// empty list -> null
assert.strictEqual(E.lookupMaxEpss([]), null);

// CWE lookup
const cwe = E.lookupCwe('CWE-79');
assert.strictEqual(cwe.title, 'Cross-site Scripting');
assert.ok(cwe.description.length > 0);
assert.strictEqual(E.lookupCwe('CWE-0000'), null);

console.log('epss: all tests passed');
