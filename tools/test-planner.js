// Self-check suite for the STRIPS planner + canonical red-team domain (zero-dep).
// Run: node tools/test-planner.js   (exit 0 = pass)
// Covers: domain parsing/grounding, a known-solvable problem with a deterministic
// expected plan, an INSOLVIBLE goal detected, and a cost-aware choice between two series.
const assert = require('assert');
const {
  solve, solveDisplay, buildRedteamDomain, groundActions, classOf, stateToArray,
} = require('./planner');

// ─── 1. Domains parse + ground (canonical orchestration domain) ───
const dom = buildRedteamDomain();
const g = groundActions(dom);
const names = g.map((x) => x.name);
assert.ok(names.includes('test_class_sqli'), 'ground test_class_sqli');
assert.ok(names.includes('test_class_authz'), 'ground test_class_authz');
assert.ok(names.includes('chain_takeover_injection'), 'ground chain action');
assert.ok(names.some((n) => n.startsWith('verify_exploitation_')), 'verify earth grounded per class');
assert.ok(!names.includes('test_class_network'), 'web-only domain excludes host-domain classes');

// generic probe cheapest on evidence: test_class xss == 2 (escalation-prone), fiddly == 3.
assert.strictEqual(g.find((x) => x.name === 'test_class_xss').cost, 2, 'escalable class probed cheaply (priority)');
assert.strictEqual(g.find((x) => x.name === 'test_class_injection').cost, 2, 'injection also cheap (priority)');
assert.strictEqual(g.find((x) => x.name === 'test_class_file-upload').cost, 3, 'fiddly class costs more');
// authz is NOT in the cheap class: unauthed authz probing is inconclusive, so the generic probe
// should cost 3 and the authed action (cost 2) is the efficient route when authed_available.
assert.strictEqual(g.find((x) => x.name === 'test_class_authz').cost, 3, 'generic authz probe not cheap (prefer authed branch)');
assert.strictEqual(g.find((x) => x.name === 'test_authed_authz').cost, 2, 'authed authz probe cheaper than generic');
assert.ok(names.includes('test_class_authn'), 'generic test survives beside authed variant');

// ─── 2. Known-solvable problem, deterministic expected plan ───
// State: surface(sqli), surface(xss), pointer surface, surface authed etc. Goal: cover all
// surfaced classes + exploit authz. The authored branch must be preferred for authz (cheaper),
// and injection must be tested so the chain can build.
const dom2 = buildRedteamDomain();
const state2 = [
  'surface(sqli)', 'surface(xss)', 'surface(authz)', 'surface(injection)',
  'surface(ssrf)', 'surface(info-disclosure)', 'authed_available',
];
const goal2 = ['found(sqli)', 'found(xss)', 'found(authz)', 'found(injection)', 'found(ssrf)', 'found(info-disclosure)', 'exploited(authz)'];

const r2a = solveDisplay(dom2, state2, goal2);
assert.strictEqual(r2a.solvable, true, 'representative goal is solvable');
assert.ok(r2a.plan.length > 0, 'plan non-empty');
const planNames = r2a.plan.map((p) => p.action);
assert.ok(planNames.includes('test_authed_authz'), 'authed branch used for authz (cheaper than generic)');
assert.ok(planNames.includes('chain_takeover_injection'), 'chain discovered deterministically');
assert.ok(r2a.plan.every((p, i) => i === 0 || r2a.plan[i].cost >= 0), 'every step has a cost');

// Determinism: same input -> same plan (run again, compare).
const r2b = solveDisplay(dom2, state2.sort(), goal2);
assert.deepStrictEqual(r2a.plan, r2b.plan, 'planner is deterministic (same input -> same plan)');

// Chain removes the need to verify alone: goal exploited(authz)+found(injection) is reached at
// a LOWER cost than verifying authz alone because the chain is cheaper (7 vs 9·2).
const chainState = ['surface(authz)', 'surface(injection)', 'authed_available'];
const chainGoal = ['exploited(authz)'];
const rc = solveDisplay(dom2, chainState, chainGoal);
assert.strictEqual(rc.solvable, true, 'chain goal reachable');
assert.ok(rc.plan.some((p) => p.action === 'chain_takeover_injection'), 'chain used for authz takeover');
assert.strictEqual(rc.cost, 2 + 2 + 6, 'authed-authz(2)+test injection(2)+chain(6)=10, cheaper than verify alone (2+9=11)');

// ─── 3. INSOLVIBLE goal detected ───
const insolv = solveDisplay(dom2, state2, ['exploited(llm)']);
assert.strictEqual(insolv.solvable, false, 'exploited(llm) unreachable -> insolvible');
assert.ok(!/solved/.test(insolv.reason), 'reason explains failure, no false plan');

// ─── 4. Cost-aware choice between two series (real decision, not order trivia) ───
// Goal done2 (only reachable once r is true). Two series reach r:
//   cheap series: cheap_direct (p->r, cost 1) then finish_r (r->done2, cost 8) = 9
//   expensive series: prep (p->q, cost 5) -> chain_to_r (q->r, cost 2) -> finish_r = 15
// Uniform-cost search must pick the 9-cost series, not the 15-cost one.
const domCost = {
  name: 'cost-choice',
  types: { n: ['a'] },
  predicates: { p: 0, q: 0, r: 0, done2: 0 },
  actions: [
    { name: 'cheap_direct', params: [], param_types: [], pre: [['p']], add: [['r']], del: [], cost: 1 },
    { name: 'prep', params: [], param_types: [], pre: [['p']], add: [['q']], del: [], cost: 5 },
    { name: 'chain_to_r', params: [], param_types: [], pre: [['q']], add: [['r']], del: [], cost: 2 },
    { name: 'finish_r', params: [], param_types: [], pre: [['r']], add: [['done2']], del: [], cost: 8 },
  ],
};
const h = solveDisplay(domCost, ['p'], ['done2']);
assert.strictEqual(h.solvable, true, 'cost-choice goal solvable');
const costSum = (plan) => plan.reduce((s, p) => s + p.cost, 0);
assert.strictEqual(costSum(h.plan), 9, 'picks the 9-cost series over the 15-cost series');
assert.ok(h.plan.some((p) => p.action === 'cheap_direct'), 'cheap direct route chosen');
assert.ok(!h.plan.some((p) => p.action === 'prep'), 'expensive detour avoided');

// classOf parity with production harness for a couple of real titles
// classOf parity with the production harness (coverage.js ordering) for real-looking titles.
assert.strictEqual(classOf({ title: 'SQL injection in id param' }), 'sqli');
assert.strictEqual(classOf({ title: 'IDOR on /api/Order allows reading other users' }), 'authz');
assert.strictEqual(classOf({ title: 'SSRF via url parameter fetches internal metadata' }), 'ssrf');
assert.strictEqual(classOf({ title: 'OTP redirect authentication bypass' }), 'authn');
assert.strictEqual(classOf({ title: 'Directory listing exposes backups' }), 'info-disclosure');
assert.strictEqual(classOf({ title: 'Insecure deserialization in signed cookie' }), 'deserialization');

console.log('test-planner.js: ALL PASS');