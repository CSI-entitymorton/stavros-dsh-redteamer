#!/usr/bin/env node
// Scope-gated Metasploit runner. Builds a resource script and drives msfconsole (spawn+parse),
// NOT msfrpcd (avoids a msgpack dependency). Every RHOST(S) is scope-checked BEFORE spawning;
// opened sessions are registered in the shared session registry and can be handed off to Sliver.
//
// ponytail: stateless per invocation + text-parsed output (no persistent RPC state). Fine for
// "load module -> run -> session". Upgrade path: msfrpcd + a msgpack client if you need state/perf.
const { spawnSync } = require('child_process');
const { loadScope, inScope } = require('./scope-guard');
const { upsertSession } = require('./sessions');

function targetsOf(opts) {
  const out = [];
  for (const k of ['RHOSTS', 'RHOST']) if (opts[k]) out.push(...String(opts[k]).split(/[ ,]+/).filter(Boolean));
  return out;
}
function buildResource(moduleName, opts) {
  const lines = ['use ' + moduleName];
  for (const [k, v] of Object.entries(opts)) if (v != null && v !== '') lines.push(`set ${k} ${v}`);
  lines.push('run -z', 'sessions -l', 'exit -y');
  return lines.join('\n') + '\n';
}
function defaultExec(rc) {
  // -q quiet, -x runs semicolon-joined commands; spawnSync captures output.
  const r = spawnSync('msfconsole', ['-q', '-x', rc.split('\n').filter(Boolean).join('; ')], { encoding: 'utf8' });
  return { stdout: (r.stdout || '') + (r.stderr || ''), status: r.status == null ? 1 : r.status };
}
function parseSessions(stdout) {
  const ids = new Set();
  const re = /(?:Meterpreter|Command shell) session (\d+) opened/gi;
  let m;
  while ((m = re.exec(stdout))) ids.add(m[1]);
  return [...ids];
}
function runModule(moduleName, opts, ctx) {
  ctx = ctx || {};
  const scope = ctx.scope || loadScope();
  const exec = ctx.exec || defaultExec;
  const targets = targetsOf(opts);
  if (!targets.length) return { ok: false, blocked: true, reason: 'no RHOST(S) target (fail closed)' };
  const bad = targets.filter((h) => !inScope('http://' + h, scope).ok);
  if (bad.length) return { ok: false, blocked: true, reason: 'out-of-scope RHOST(S)', hosts: bad };
  const rc = buildResource(moduleName, opts);
  const res = exec(rc);
  const sessions = parseSessions(res.stdout || '');
  for (const sid of sessions)
    upsertSession({ id: 'msf-' + sid, host: targets[0], obtained_via: 'msf:' + moduleName, status: 'active' });
  return { ok: res.status === 0, sessions, stdout: res.stdout };
}
module.exports = { targetsOf, buildResource, parseSessions, runModule };
