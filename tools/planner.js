#!/usr/bin/env node
// Deterministic STRIPS forward state-space planner (zero-dep Node) + the canonical
// red-team orchestration domain, on the CHECKMATE model: instead of the LLM orchestrator
// guessing "which class to test next", a classic planner orders the ground test actions
// over REAL harness state (surface ← candidates, found ← findings, authed ← auth.json).
//
//   node tools/planner.js solve <domainfile.json> <initfile.json>   # print plan or "insolvibile"
//   node tools/planner.js demo <host>                                # plan a real host from reports/
//
// Mini-domain language (JSON, parsed here):
// {
//   "name": "...",
//   "types":   { "class": ["sqli","xss",...] },            // type -> constants
//   "predicates": { "surface": ["class"], "found": ["class"], "authed_available": [] },
//   "actions": [
//     { "name":"test_class","params":["c"],"param_types":["class"],
//       "pre":[["surface","?c"]], "add":[["found","?c"],["covered","?c"]],"del":[["surface","?c"]],
//       "cost": 2, "reason":"Probe class {0}: it has live candidate surface now (cheap, escalates)." }
//   ],
//   "costs": { "test_class": { "authz":2, "xss":4 } }      // optional binding-aware costs override
// }
// Action cost can be a plain number OR a per-{first-param} map in domain.costs (lower = higher
// priority). Search is uniform-cost (Dijkstra) keyed by (f, seq) so ties break FIFO → the same
// input ALWAYS yields the same plan. Bounded by nodeLimit/stepLimit.
//
// Cost model (the "priority" real pentesters apply):
//   - test_class(c): cheap-to-probe + escalation-prone classes are cheapest (sqli/xss/ssrf/
//     injection/authz = 2) so they are probed before fiddly classes (3). authz generic is 4 for
//     web apps because unauthenticated authz probing is inconclusive without a token.
//   - test_authed_authz: 2 — the proper BOLA/BFLA method once an identity exists (auth.json).
//     Cheaper than generic authz, so the planner prefers it when authed_available — the branch.
//   - verify_exploitation(c): 9 — re-firing live to raise suspected→proven costs effort.
//   - chain_takeover (injection|info-disclosure amplifying authz): 6 — cheaper than verifying
//     authz alone (9) BECAUSE the amplifying class is already found; models the hand-built
//     OTP-redirect/GraphQL-BOLA chains (chain.js) being discovered deterministically.
'use strict';
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Web-class coverage domains. Mirrors the classes real harness state is derived
// from (tools/coverage.js CLASSES ∩ map.js candidate classes). Host-domain classes
// (cloud/network/wireless/postex) are out of scope for the web coverage goal.
// ---------------------------------------------------------------------------
const WEB_CLASSES = [
  'sqli', 'xss', 'ssrf', 'injection', 'authn', 'authz', 'csrf', 'idor', 'bola',
  'file-upload', 'path-traversal', 'deserialization', 'info-disclosure', 'config',
  'crypto', 'logic', 'llm', 'mcp', 'supply-chain', 'smuggling',
];

// per-class cost for the generic web-class probe (lower = higher priority).
// authz is deliberately NOT in the cheap list: unauthenticated authz probing is inconclusive
// without an identity, so the generic probe costs 3. When authed_available, the dedicated
// test_authed_authz action costs 2 — the planner then prefers the authed branch.
const ESCALATION_CLASSES = ['sqli', 'xss', 'ssrf', 'injection'];
const CLASS_COST = {};
for (const c of WEB_CLASSES) {
  CLASS_COST[c] = ESCALATION_CLASSES.includes(c) ? 2 : 3;
}
CLASS_COST.authz = 3; // unauthed authz needs token tricks / may end inconclusive

// ---------------------------------------------------------------------------
// Mini-domain parsing / grounding
// ---------------------------------------------------------------------------

function parseBool(v) { return !!v; }
function predOf(domain, name) { return domain.predicates[name] || (domain.predicates[name] = 1); }

// Tokenize an atom given in [pred, a, b] array form -> canonical "pred(a,b)" string.
function atomToString(atom) {
  const s = atom.slice();
  const p = s.shift();
  return p + (s.length ? '(' + s.join(',') + ')' : '');
}

// Substitute ?vars in an atom array with the parameter binding.
function subst(atom, bind) {
  // atoms reference params as '?c'; the binding map is keyed by bare 'c'.
  return atom.map((a) => {
    const key = typeof a === 'string' && a[0] === '?' && a.length > 1 ? a.slice(1) : null;
    return key != null && bind[key] != null ? bind[key] : a;
  });
}

// Enumerate all grounded actions from the parameterized templates.
function groundActions(domain) {
  const constants = domain.types[Object.keys(domain.types)[0]] || [];
  const grounded = [];
  for (const a of domain.actions) {
    const params = a.params || [];
    const types = a.param_types || params.map(() => Object.keys(domain.types)[0]);
    const rec = (i, bind) => {
      if (i === params.length) {
        const name = a.name + (bind[params[0]] != null ? '_' + bind[params[0]] : '');
        // binding-aware cost override (domain.costs[action][firstParam])
        let cost = a.cost != null ? a.cost : 1;
        const over = (domain.costs || {})[a.name];
        if (over && bind[params[0]] != null && over[bind[params[0]]] != null) cost = over[bind[params[0]]];
        grounded.push({
          name,
          base: a.name,
          bind,
          cost: Number(cost),
          pre: a.pre.map((atom) => atomToString(subst(atom, bind))).sort(),
          add: a.add.map((atom) => atomToString(subst(atom, bind))).sort(),
          del: a.del.map((atom) => atomToString(subst(atom, bind))).sort(),
          params: params.map((p) => bind[p]),
          reason: a.reason,
        });
        return;
      }
      for (const c of (domain.types[types[i]] || [])) {
        bind[params[i]] = c;
        rec(i + 1, bind);
        delete bind[params[i]];
      }
    };
    rec(0, {});
  }
  return grounded;
}

// A grounded action is applicable iff all preconditions hold in the state (Set).
function applicable(g, state) {
  return g.pre.every((a) => state.has(a));
}

function apply(state, g) {
  const ns = new Set(state);
  for (const a of g.del) ns.delete(a);
  for (const a of g.add) ns.add(a);
  return ns;
}

// ---------------------------------------------------------------------------
// Min-heap keyed by (f = g, seq) — uniform-cost search with deterministic
// FIFO tie-breaking. Insertion sequence is fixed, so the plan is deterministic.
// ---------------------------------------------------------------------------
class Heap {
  constructor() { this.a = []; this.seq = 0; this.size = 0; }
  push(key, item) {
    const node = { key: key.map((x) => (x == null ? Infinity : x)), seq: this.seq++, item };
    const a = this.a;
    a.push(node); this.size++;
    let i = a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (lt(node, a[p])) { a[i] = a[p]; i = p; } else break;
    }
    a[i] = node;
  }
  pop() {
    const a = this.a;
    if (!a.length) return undefined;
    const top = a[0];
    const last = a.pop(); this.size--;
    if (a.length) {
      let i = 0;
      a[0] = last;
      for (;;) {
        const l = 2 * i + 1, r = l + 1;
        let m = i;
        if (l < a.length && lt(a[l], a[m])) m = l;
        if (r < a.length && lt(a[r], a[m])) m = r;
        if (m === i) break;
        const tmp = a[m]; a[m] = a[i]; a[i] = tmp; i = m;
      }
    }
    return top;
  }
}
function lt(a, b) {
  for (let i = 0; i < a.key.length; i++) {
    if (a.key[i] !== b.key[i]) return a.key[i] < b.key[i];
  }
  return a.seq < b.seq;
}

// Sound reachability fast-path: forward closure over ground actions (ignore ordering). If a goal
// atom is NOT reachable, no plan exists — return insolvibile instantly instead of blowing the
// node budget on exploration (the anti-explosion guarantee). Over-approximates, so it never
// rejects an actually-solvable goal; when it does NOT prune we still run the exact search.
function unreachableGoalAtom(grounded, goalArr, initial) {
  // An atom is reachable if it's in the initial state or appears in an action's adds once that
  // action's preconditions are all reachable (forward closure over ground actions).
  const reachable = new Set(initial);
  let changed = true;
  while (changed) {
    changed = false;
    for (const a of grounded) {
      if (a.pre.every((p) => reachable.has(p))) {
        for (const ad of a.add) {
          if (!reachable.has(ad)) { reachable.add(ad); changed = true; }
        }
      }
    }
  }
  return goalArr.find((g) => !reachable.has(g)) || null;
}

// Uniform-cost forward search. Returns { solvable, plan, cost, explored, reason }.
function solve(domain, state0, goal, opts) {
  opts = opts || {};
  const nodeLimit = opts.nodeLimit || 20000;
  const stepLimit = opts.stepLimit || 25;
  const grounded = groundActions(domain);
  const start = new Set(state0);
  const goalArr = (Array.isArray(goal) ? goal : [goal]).map((g) =>
    Array.isArray(g) ? atomToString(g) : String(g));
  const keyOf = (s) => [...s].sort().join('|');
  // Fast insolvibile detection: some goal atom is unproducible.
  const dead = unreachableGoalAtom(grounded, goalArr, start);
  if (dead) {
    return { solvable: false, plan: null, cost: Infinity, explored: 0, reason: 'goal atom unreachable: ' + dead };
  }
  const startKey = keyOf(start);
  if (goalArr.every((g) => start.has(g))) {
    return { solvable: true, plan: [], cost: 0, explored: 0, reason: 'goal already satisfied' };
  }
  const heap = new Heap();
  // node: { state, g, parent, action, depth }
  heap.push([0], { state: start, g: 0, parent: null, action: null, depth: 0, key: startKey });
  const best = new Map([[startKey, 0]]); // state key -> best g reached
  let explored = 0;
  while (heap.size > 0) {
    if (explored >= nodeLimit) {
      return { solvable: false, plan: null, cost: Infinity, explored, reason: 'node limit exceeded (' + nodeLimit + ')' };
    }
    const cur = heap.pop().item;
    if (!specKey(cur.key)) continue; // stale (a better g already reached)
    explored++;
    if (cur.depth > stepLimit) {
      return { solvable: false, plan: null, cost: Infinity, explored, reason: 'plan too long (step limit ' + stepLimit + ')' };
    }
    if (goalArr.every((g) => cur.state.has(g))) {
      const plan = [];
      let n = cur;
      while (n.action) { plan.unshift(n.action); n = n.parent; }
      return { solvable: true, plan, cost: cur.g, explored, reason: 'solved' };
    }
    for (const g of grounded) {
      if (!applicable(g, cur.state)) continue;
      const ns = apply(cur.state, g);
      const k = keyOf(ns);
      const ng = cur.g + g.cost;
      const prev = best.get(k);
      if (prev != null && prev <= ng) continue;
      best.set(k, ng);
      heap.push([ng], { state: ns, g: ng, parent: cur, action: g, depth: cur.depth + 1, key: k });
    }
  }
  return { solvable: false, plan: null, cost: Infinity, explored, reason: 'state space exhausted' };
}
function specKey(k) { return k; }

// ---------------------------------------------------------------------------
// solveDisplay(domain, state0, goal) — structured, display-ready result.
// ---------------------------------------------------------------------------
function solveDisplay(domain, state0, goal, opts) {
  const r = solve(domain, state0, goal, opts);
  if (!r.solvable) {
    return { solvable: false, goal, cost: r.cost, explored: r.explored, reason: r.reason, plan: null };
  }
  const plan = r.plan.map((g, i) => ({
    step: i + 1,
    action: g.base,
    name: g.name,
    class: g.bind && Object.keys(g.bind).length ? g.bind[Object.keys(g.bind)[0]] : undefined,
    params: g.params,
    cost: g.cost,
    reason: g.reason,
    pre: g.pre,
    add: g.add,
  }));
  return { solvable: true, goal: [...goal], cost: r.cost, explored: r.explored, reason: r.reason, plan };
}

// ---------------------------------------------------------------------------
// Canonical red-team orchestration domain.
// ---------------------------------------------------------------------------
function buildRedteamDomain(opts) {
  opts = opts || {};
  const classes = opts.classes || WEB_CLASSES;
  const includeHostDomain = !!opts.includeHostDomain;
  const all = includeHostDomain
    ? classes.concat(['cloud', 'network', 'wireless', 'postex', 'chain', 'exceptional'])
    : classes;

  return {
    name: 'redteam-weborch',
    types: { class: all },
    predicates: {
      surface: 1, found: 1, covered: 1, exploited: 1, authed_available: 0,
    },
    costs: { test_class: CLASS_COST },
    actions: [
      {
        // Generic web-class probe: consumes live candidate surface, records a finding.
        name: 'test_class',
        params: ['c'], param_types: ['class'],
        pre: [['surface', '?c']],
        add: [['found', '?c'], ['covered', '?c']],
        del: [['surface', '?c']],
        reason: 'Probe {0}: it has live candidate surface now and is cheap to test.',
      },
      {
        // Authed branch: BOLA/BFLA/broken-authorization testing needs an identity (auth.json).
        // A FIXED action for authz (identity-scoped), cheaper than the generic authz probe.
        name: 'test_authed_authz',
        params: [], param_types: [],
        pre: [['surface', 'authz'], ['authed_available']],
        add: [['found', 'authz'], ['covered', 'authz']],
        del: [['surface', 'authz']],
        cost: 2,
        reason: 'Test authz on the authed surface: an identity exists (auth.json), so BOLA/BFLA probing is cheap.',
      },
      {
        // Re-fire a found class live to raise suspected → proven_impact (verification duty).
        name: 'verify_exploitation',
        params: ['c'], param_types: ['class'],
        pre: [['found', '?c']],
        add: [['exploited', '?c']],
        del: [],
        cost: 9,
        reason: 'Verify {0} live to prove real impact (verified = reportable).',
      },
      {
        // Chain: found(authz) amplified by found(injection) → deterministic ATO-style takeover,
        // cheaper than verifying authz alone (mirrors chain.js leaked-secret/injection rules).
        name: 'chain_takeover_injection',
        params: [], param_types: [],
        pre: [['found', 'authz'], ['found', 'injection']],
        add: [['exploited', 'authz']],
        del: [],
        cost: 6,
        reason: 'Chain takeover: found authz + found injection combine (OTP/BOLA-style) into an exploited account takeover.',
      },
      {
        // Chain via leaked-key info-disclosure (chain.js "leaked-secret authorization bypass").
        name: 'chain_takeover_disclosure',
        params: [], param_types: [],
        pre: [['found', 'authz'], ['found', 'info-disclosure']],
        add: [['exploited', 'authz']],
        del: [],
        cost: 6,
        reason: 'Chain takeover: found authz + leaked info-disclosure satisfy the auth the broken check relied on.',
      },
    ],
  };
}

// Attempt to build a ground initial state from REAL harness artifacts for a host.
// Derives facts using the exact invariants coverage.js/map.js/gate.js use:
//   surface(c)  ←  reports/<host>-map.json candidates[c] (>0)      (map.js candidates)
//   found(c)    ←  reports/findings.jsonl classOf(f)===c           (coverage.js)
//   authed_available ← reports/auth.json exists                     (gate authed)
// Falls back to a synthetic state when files are missing (offline, no network).
function stateFromHost(host, opts) {
  opts = opts || {};
  const reports = opts.reportsDir || path.join(__dirname, '..', 'reports');
  const state = new Set(['surface(sqlli_probe)']); // placeholder removed below
  state.clear();
  let candidates = {};
  try {
    candidates = JSON.parse(fs.readFileSync(path.join(reports, host + '-map.json'), 'utf8')).candidates;
  } catch {}

  // surface(c): count candidate params/urls for the class (matches coverage.js cand>0).
  for (const c of Object.keys(candidates || {})) {
    if (Array.isArray(candidates[c]) && candidates[c].length && WEB_CLASSES.includes(c)) state.add('surface(' + c + ')');
  }
  const mapHost = host + '-map.json';
  if (!fs.existsSync(path.join(reports, mapHost))) {
    // Synthetic host so demo/test behave offline: representative surface. authz surface gets
    // the authed branch (authed_available) and injection surface lets the chain_takeover build.
    state.add('surface(sqli)');
    state.add('surface(xss)');
    state.add('surface(authz)');
    state.add('surface(ssrf)');
    state.add('surface(injection)');
    state.add('surface(file-upload)');
    state.add('surface(info-disclosure)');
    state.add('authed_available');
    return { host, synthetic: true, state };
  }

  // found(c): scan findings.jsonl, classOf() assigns the class (coverage.js).
  let findings = [];
  try {
    findings = fs.readFileSync(path.join(reports, 'findings.jsonl'), 'utf8').split('\n').filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch {}
  for (const f of findings) {
    if (f.host && String(f.host) !== host && !String(f.host).includes(host)) continue;
    const c = classOf(f);
    if (WEB_CLASSES.includes(c)) state.add('found(' + c + ')');
  }
  // authed_available: auth.json exists (gate authed).
  for (const p of [path.join(reports, 'auth.json'), path.join(reports, host + '-auth.json')]) {
    if (fs.existsSync(p)) state.add('authed_available');
  }
  return { host, synthetic: false, state };
}

// Minimal classOf() so stateFromHost is self-contained (offline, mirrors coverage.js ordering).
function classOf(f) {
  const t = String(f.cwe || f.title || f.type || '').toLowerCase();
  if (/sql|sqli/.test(t)) return 'sqli';
  if (/xss/.test(t)) return 'xss';
  if (/ssrf/.test(t)) return 'ssrf';
  if (/injection|command/.test(t)) return 'injection';
  if (/auth.*(bypass|reset|otp|session|jwt)|login/i.test(t)) return 'authn';
  if (/authorization|broken function|bfba|(endpoint.*admin|admin.*endpoint)|idor|bola|bfla/i.test(t)) return 'authz';
  if (/csrf/.test(t)) return 'csrf';
  if (/llm|prompt injection|genai|agentic|jailbreak|model/.test(t)) return 'llm';
  if (/mcp|tool[- ]misuse|json-?rpc.*mcp|context window/.test(t)) return 'mcp';
  if (/supply[- ]chain|third[- ]party|dependency|sbom/.test(t)) return 'supply-chain';
  if (/smuggl|desync|cl\.te|te\.cl|te\.te|te\.chunked/.test(t)) return 'smuggling';
  if (/upload/.test(t)) return 'file-upload';
  if (/travers|lfi/.test(t)) return 'path-traversal';
  if (/deserial/.test(t)) return 'deserialization';
  if (/disclos|leak|expos|directory listing/.test(t)) return 'info-disclosure';
  if (/config|misconfig|default cred/.test(t)) return 'config';
  if (/crypto|jwt|hash|weak key/.test(t)) return 'crypto';
  if (/logic|race|state|business/.test(t)) return 'logic';
  return 'other';
}

function stateToArray(state) { return [...state].sort(); }

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function cmdSolve(domainFile, initFile) {
  let domain;
  try {
    domain = JSON.parse(fs.readFileSync(domainFile, 'utf8'));
  } catch (e) { console.error('cannot read domain ' + domainFile + ': ' + e.message); process.exit(2); }
  let init;
  try {
    init = JSON.parse(fs.readFileSync(initFile, 'utf8'));
  } catch (e) { console.error('cannot read init ' + initFile + ': ' + e.message); process.exit(2); }
  const state0 = init.state || [];
  const goal = init.goal || [];
  const r = solveDisplay(domain, state0, goal);
  if (!r.solvable) {
    console.log('insolvibile');
    console.log('  reason: ' + r.reason + ' (explored ' + r.explored + ' nodes)');
    process.exit(1);
  }
  console.log('piano (cost=' + r.cost + ', nodes=' + r.explored + '):');
  for (const p of r.plan) console.log('  ' + p.step + '. ' + p.name + '  [' + p.pre.join(', ') + ' -> +' + p.add.join(',+') + ']');
  process.exit(0);
}

function cmdDemo(host, reportsDir) {
  const dom = buildRedteamDomain();
  const ctx = reportsDir ? stateFromHost(host, { reportsDir }) : stateFromHost(host);
  const arcs = ctx.state.has('authed_available');
  const src = ctx.synthetic ? '(synthetic offline state)' : '(from ' + reportsDir || 'reports' + '/' + host + '-map.json + findings.jsonl)';
  console.log('# Planner demo — host ' + host + ' ' + src);
  console.log('\ninitial state:');
  console.log('  ' + stateToArray(ctx.state).join('\n  '));
  console.log('\ncoverage goal: every surfaced class must be found (kills coverage "missed");\n' +
              '              plus exploit one escalation class to broken proof.');

  const goal = [];
  for (const a of ctx.state) {
    const m = /^surface\(([a-z0-9-]+)\)$/.exec(a);
    if (m) goal.push('found(' + m[1] + ')');
  }
  goal.push('exploited(authz)');
  const g = stateToArray(new Set(ctx.state));
  console.log('\ngoal: ' + goal.join(' AND '));
  const r = solveDisplay(dom, g, goal);
  console.log('\n=== plan (cost=' + r.cost + ', explored=' + r.explored + ' nodes) ===');
  if (!r.solvable) { console.log('insolvibile — reason: ' + r.reason); return; }
  for (const p of r.plan) {
    const why = formatReason(p.reason, p);
    console.log('[' + p.step + '] ' + p.name);
    console.log('    -> ' + why);
    console.log('       pre: ' + p.pre.join(', '));
  }

  // Demonstrate detection of an INSOLVIBLE goal.
  console.log('\n\n=== insolvable case: goal exploited(llm) with neither llm surface nor a route to it ===');
  const badGoal = ['exploited(llm)'];
  const bad = solveDisplay(dom, g, badGoal);
  console.log('goal: ' + badGoal.join(' AND '));
  console.log(bad.solvable ? 'soluble (unexpected!)' : 'insolvibile — reason: ' + bad.reason);
}

function formatReason(tpl, p) {
  if (!tpl) return p.name;
  return tpl.replace(/\{(\d)\}/g, (_, i) => (p.params && p.params[i] != null ? p.params[i] : ''));
}

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (cmd === 'solve' && args[1] && args[2]) { cmdSolve(args[1], args[2]); }
  else if (cmd === 'demo' && args[1]) { cmdDemo(args[1], process.env.STAVROS_REPORTS); }
  else {
    console.error('usage: node tools/planner.js solve <domainfile.json> <initfile.json>');
    console.error('       node tools/planner.js demo <host>');
    process.exit(2);
  }
}

if (require.main === module) main();

module.exports = {
  WEB_CLASSES, CLASS_COST, solve, solveDisplay, buildRedteamDomain, groundActions,
  applicable, apply, stateFromHost, classOf, stateToArray, atomToString,
};