#!/usr/bin/env node
// CVSS v3.1 base score calculator (zero-dep, offline). Used by the reporter to attach a
// real CVSS vector/score to every finding instead of guessing.
//   node tools/cvss.js 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
//   -> { vector, base_score: 9.8, severity: 'Critical', impact, exploitability }
// Values (CVSS v3.1 spec):
//   AV: N(0.85) A(0.62) L(0.55) P(0.2)
//   AC: L(0.77) H(0.44)
//   PR: N(0.85) L(0.62/0.68) H(0.27/0.5)   <- second value when Scope=Changed
//   UI: N(0.85) R(0.62)
//   C/I/A: N(0) L(0.22) H(0.56)
const METRICS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 },
  PR_S: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  C: { N: 0, L: 0.22, H: 0.56 },
  I: { N: 0, L: 0.22, H: 0.56 },
  A: { N: 0, L: 0.22, H: 0.56 },
};
const REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

function roundup1(x) {
  return Math.ceil(x * 10) / 10;
}

function severityOf(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0) return 'Low';
  return 'None';
}

// vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
function calculate(vector) {
  const kv = {};
  for (const part of String(vector).split('/')) {
    const [k, v] = part.split(':');
    if (k && v) kv[k] = v.toUpperCase();
  }
  for (const m of REQUIRED) {
    if (!kv[m]) throw new Error('missing metric ' + m + ' in vector: ' + vector);
  }
  const S = kv.S;
  if (S !== 'U' && S !== 'C') throw new Error('S must be U or C');
  const pr = S === 'C' ? METRICS.PR_S : METRICS.PR;
  const av = METRICS.AV[kv.AV], ac = METRICS.AC[kv.AC], pru = pr[kv.PR], ui = METRICS.UI[kv.UI];
  const c = METRICS.C[kv.C], i = METRICS.I[kv.I], a = METRICS.A[kv.A];
  for (const [name, val] of [['AV', av], ['AC', ac], ['PR', pru], ['UI', ui], ['C', c], ['I', i], ['A', a]]) {
    if (val == null) throw new Error('invalid value for ' + name + ': ' + kv[name]);
  }
  const ISS = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = S === 'U' ? 6.42 * ISS : 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
  const exploitability = 8.22 * av * ac * pru * ui;
  const base = S === 'U'
    ? roundup1(Math.min(impact + exploitability, 10))
    : roundup1(Math.min(1.08 * (impact + exploitability), 10));
  return {
    vector: vector.toUpperCase(),
    base_score: +base.toFixed(1),
    severity: severityOf(base),
    impact: +impact.toFixed(4),
    exploitability: +exploitability.toFixed(4),
    scope: S,
  };
}

const vector = process.argv[2];
if (require.main === module) {
  if (!vector) {
    console.error("usage: node tools/cvss.js 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'");
    process.exit(2);
  }
  try {
    console.log(JSON.stringify(calculate(vector), null, 2));
  } catch (e) {
    console.error(JSON.stringify({ error: e.message }));
    process.exit(1);
  }
}

module.exports = { calculate, severityOf, roundup1 };
