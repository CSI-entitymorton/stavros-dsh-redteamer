#!/usr/bin/env node
// Session registry = teardown ledger. Single source of truth on C2 sessions and the
// artifacts they leave on real hosts, so cleanup is deterministic. Mutable -> single
// JSON file (atomic tmp+rename). Env override SESSIONS_JSON for tests.
const fs = require('fs');
const path = require('path');

function regPath(file) {
  return file || process.env.SESSIONS_JSON || path.join(__dirname, '..', 'reports', 'sessions.json');
}
function loadRegistry(file) {
  try {
    return JSON.parse(fs.readFileSync(regPath(file), 'utf8'));
  } catch {
    return { sessions: {} };
  }
}
function saveRegistry(reg, file) {
  const p = regPath(file);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(reg, null, 2));
  fs.renameSync(tmp, p);
}
function upsertSession(sess, file) {
  const reg = loadRegistry(file);
  const prev = reg.sessions[sess.id] || {};
  const merged = Object.assign({ status: 'pending', artifacts: [] }, prev, sess);
  merged.status = sess.status || prev.status || 'pending';
  merged.artifacts = prev.artifacts || sess.artifacts || [];
  reg.sessions[sess.id] = merged;
  saveRegistry(reg, file);
  return merged;
}
function setStatus(id, status, file) {
  const reg = loadRegistry(file);
  if (!reg.sessions[id]) throw new Error('unknown session ' + id);
  reg.sessions[id].status = status;
  saveRegistry(reg, file);
}
function addArtifact(id, artifact, file) {
  const reg = loadRegistry(file);
  if (!reg.sessions[id]) throw new Error('unknown session ' + id);
  (reg.sessions[id].artifacts = reg.sessions[id].artifacts || []).push(
    Object.assign({ ts: new Date().toISOString(), removed: false }, artifact)
  );
  saveRegistry(reg, file);
}
function openArtifacts(id, file) {
  const s = loadRegistry(file).sessions[id];
  return ((s && s.artifacts) || []).filter((a) => a.removed !== true);
}
function markArtifactRemoved(id, index, file) {
  const reg = loadRegistry(file);
  const s = reg.sessions[id];
  if (s && s.artifacts && s.artifacts[index]) s.artifacts[index].removed = true;
  saveRegistry(reg, file);
}
module.exports = { loadRegistry, saveRegistry, upsertSession, setStatus, addArtifact, openArtifacts, markArtifactRemoved };
