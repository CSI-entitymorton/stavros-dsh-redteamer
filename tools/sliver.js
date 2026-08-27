#!/usr/bin/env node
// Scope- and tier-gated Sliver operator. Wraps the sliver-client binary (spawn+parse). Each
// command is classified (c2-guard): auto runs; confirm-tier is refused without --confirm; lateral
// commands' destination hosts are scope-checked. Artifact-producing commands (persist/upload) are
// recorded in the session registry so cleanup() can remove them.
//
// ponytail: text-parsed sliver-client output (brittle). Upgrade path: gRPC operator API
// (@grpc/grpc-js + Sliver protobufs) if parsing proves too fragile.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { loadScope } = require('./scope-guard');
const { enforce, pivotInScope } = require('./c2-guard');
const { addArtifact, openArtifacts, markArtifactRemoved, loadRegistry } = require('./sessions');

function loadListeners(file) {
  const p = file || path.join(__dirname, '..', 'c2.json');
  try { return (JSON.parse(fs.readFileSync(p, 'utf8')).listeners) || {}; } catch { return {}; }
}
function defaultExec(sessionId, command) {
  const r = spawnSync('sliver-client', ['--session', sessionId, '--command', command], { encoding: 'utf8' });
  return { stdout: (r.stdout || '') + (r.stderr || ''), status: r.status == null ? 1 : r.status };
}
const ARTIFACT_RE = /\b(persist|persistence|autorun|service[- ]?create|schtask|crontab|startup|upload)\b/i;

function runCmd(sessionId, command, ctx) {
  ctx = ctx || {};
  const scope = ctx.scope || loadScope();
  const exec = ctx.exec || defaultExec;
  const g = enforce(command, { confirm: ctx.confirm }, scope);
  if (!g.ok) return { ok: false, blocked: true, reason: g.reason };
  if (g.actionClass === 'lateral') {
    const p = pivotInScope(command, scope);
    if (!p.ok) return { ok: false, blocked: true, reason: 'pivot target out of scope', hosts: p.badHosts };
  }
  const res = exec(sessionId, command);
  if (ARTIFACT_RE.test(command))
    addArtifact(sessionId, { type: g.actionClass, location: command, removal: 'MANUAL: undo `' + command + '`' });
  return { ok: res.status === 0, output: res.stdout, actionClass: g.actionClass };
}

// Execute a privesc CATALOG CHECK by id. The command text is resolved from
// tools/privesc-catalog.json INSIDE this function (never accepted as a freeform
// argument), so the read-only probe set is exactly what that file says and the
// generic classifier stays untouched for everything else. The session must be
// registered, active, and its host in scope.
function execCheck(sessionId, checkId, ctx) {
  ctx = ctx || {};
  let entry;
  try {
    const cat = JSON.parse(fs.readFileSync(path.join(__dirname, 'privesc-catalog.json'), 'utf8'));
    entry = cat.checks.find((e) => e.id === checkId);
  } catch (e) {
    return { ok: false, blocked: true, reason: 'catalog unreadable: ' + e.message };
  }
  if (!entry) return { ok: false, blocked: true, reason: 'unknown check id: ' + checkId };
  const cmd = entry.cmds[ctx.index || 0];
  const reg = loadRegistry();
  const sess = reg.sessions[sessionId];
  if (!sess || sess.status !== 'active') return { ok: false, blocked: true, reason: 'session not found or not active: ' + sessionId };
  const scope = ctx.scope || loadScope();
  if (!require('./scope-guard').inScope('http://' + sess.host, scope).ok)
    return { ok: false, blocked: true, reason: 'session host out of scope: ' + sess.host };
  const exec = ctx.exec || defaultExec;
  const res = exec(sessionId, cmd);
  return { ok: res.status === 0, blocked: false, id: checkId, output: res.stdout };
}

function cleanup(sessionId, ctx) {
  ctx = ctx || {};
  const exec = ctx.exec || defaultExec;
  const all = (loadRegistry().sessions[sessionId] || {}).artifacts || [];
  let removed = 0;
  all.forEach((a, i) => {
    if (a.removed === true) return;
    exec(sessionId, a.removal || ('rm ' + a.location));
    markArtifactRemoved(sessionId, i);
    removed++;
  });
  return { removed, remaining: openArtifacts(sessionId).length };
}
module.exports = { runCmd, execCheck, cleanup, loadListeners };
