// Self-check: desync.js probe payloads are structurally correct and the detector closures
// are honest. Pure unit tests (no network, no target).
// Run: node tools/test-desync.js
const assert = require('assert');
const D = require('./desync');

// buildPayloads returns the two canonical probe variants
const payloads = D.buildPayloads('UNITMARKER');
assert.strictEqual(payloads.length, 2);
const names = payloads.map((p) => p.name).sort();
assert.deepStrictEqual(names, ['CL.TE', 'TE.CL']);

// each raw request:
//  - is a well-formed HTTP/1.1 request with Host + TE/CL headers
//  - embeds the marker in a smuggled follow-up request
for (const p of payloads) {
  assert.ok(/^POST \/ HTTP\/1\.1\r\n/i.test(p.raw), `${p.name}: starts as POST`);
  assert.ok(/Host: \{\{HOST\}\}\r\n/i.test(p.raw), `${p.name}: has Host`);
  assert.ok(/Content-Length: \d+\r\n/i.test(p.raw), `${p.name}: has Content-Length`);
  assert.ok(/Transfer-Encoding: chunked\r\n/i.test(p.raw), `${p.name}: has Transfer-Encoding`);
  assert.ok(p.raw.includes('UNITMARKER'), `${p.name}: embeds the marker`);
  // CL.TE and TE.CL must differ (they set the lengths differently)
}

// distinctness between the two probes
assert.notStrictEqual(payloads[0].raw, payloads[1].raw, 'CL.TE and TE.CL payloads differ');

// detect() is called with the primary probe response plus a nested `follow` (the follow-up
// request result on the same socket) — the desync manifests in the follow-up. A clean
// follow-up must NOT be judged likely; a marker-echo or backend abort is a weak positive.
for (const p of payloads) {
  const clean = p.detect({ body: '', status: null, timedOut: false, follow: { body: '', status: 200, timedOut: false, hasMarker: false } });
  assert.strictEqual(clean, false, `${p.name}: clean follow-up not flagged`);

  const markerEcho = p.detect({ body: '', status: null, timedOut: false, follow: { body: 'UNITMARKER', status: 200, timedOut: false, hasMarker: true } });
  assert.strictEqual(markerEcho, true, `${p.name}: marker reflection on follow-up flagged`);

  const backendAbort = p.detect({ body: '', status: null, timedOut: false, follow: { body: '', status: 400, timedOut: false, hasMarker: false } });
  assert.strictEqual(backendAbort, true, `${p.name}: backend abort (400) flagged as suspect`);
}

// MARKER() is unique per call
assert.notStrictEqual(D.MARKER(), D.MARKER());
assert.ok(/^[A-Za-z0-9-]+$/.test(D.MARKER()), 'marker is URL-safe');

console.log('desync: all tests passed');