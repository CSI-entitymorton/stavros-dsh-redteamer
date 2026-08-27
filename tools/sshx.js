#!/usr/bin/env node
// Scope- and tier-gated SSH channel for Linux hosts. The practical breach/postex
// path on physical boxes when you hold a looted key or credential: every command
// is classified by c2-guard (auto runs; confirm-tier refused without --confirm),
// the destination host must be in scope, and a successful connection registers an
// `ssh-<user>@<host>` session in the shared teardown ledger (reports/sessions.json)
// so stavros-cleanup sees it like any C2 session.
//
// ponytail: spawns the system ssh client per invocation (stateless). No multiplexing,
// no persistent master socket yet. Password auth requires sshpass reading the secret
// from a FILE (-f) — never a CLI argument (process listings are loot for the other side).
const fs = require('fs');
const { spawnSync } = require('child_process');
const path = require('path');
const { loadScope, inScope } = require('./scope-guard');
const { enforce, pivotInScope } = require('./c2-guard');
const { loadRegistry, upsertSession } = require('./sessions');

function auditFile(file) {
  return file || process.env.HOSTOPS_AUDIT || path.join(__dirname, '..', 'reports', 'tmp', 'hostops-audit.jsonl');
}
function audit(entry, file) {
  const p = auditFile(file);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.appendFileSync(p, JSON.stringify(Object.assign({ ts: new Date().toISOString(), tool: 'sshx' }, entry)) + '\n');
}

function buildArgs(host, conn, command) {
  const c = conn || {};
  const args = [
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ConnectTimeout=8',
    '-o', 'NumberOfPasswordPrompts=1',
  ];
  if (c.key) { args.push('-i', c.key); args.push('-o', 'BatchMode=yes'); }
  if (c.port && Number(c.port) !== 22) args.push('-p', String(c.port));
  const prefix = c.passFile ? ['sshpass', '-f', String(c.passFile)] : [];
  const target = `${c.user || 'root'}@${host}`;
  return { prefix: prefix.concat(['ssh', ...args, target, command]), display: `<hidden>${command}` };
}

function defaultExec(fullArgs) {
  const r = spawnSync(fullArgs[0], fullArgs.slice(1), { encoding: 'utf8', timeout: 30000 });
  return { stdout: (r.stdout || '') + (r.stderr || ''), status: r.status == null ? 1 : r.status };
}

function resolveSession(target, file) {
  // accepts a full session id (`ssh-root@h`) or a bare host (unique user assumed)
  const reg = loadRegistry(file);
  const ids = Object.keys(reg.sessions);
  let id = reg.sessions[target] ? target : null;
  if (!id) id = ids.find((k) => k === 'ssh-' + target) || ids.find((k) => k.endsWith('@' + target));
  const sess = id ? reg.sessions[id] : null;
  return sess && sess.channel === 'ssh' ? Object.assign({ id }, sess) : null;
}

// Main gated entry: exec(hostOrSessionId, command, ctx).
function exec(target, command, ctx) {
  ctx = ctx || {};
  const scope = ctx.scope || loadScope();
  // Resolve connection: explicit ctx.conn wins; else an existing ssh session for this id/host.
  const known = resolveSession(target, ctx.sessionsFile);
  const host = ctx.host || (known ? known.host : target);
  const conn = ctx.conn || (known ? known.conn : { user: ctx.user || 'root', port: ctx.port, key: ctx.key, passFile: ctx.passFile });

  const sc = inScope('http://' + host, scope);
  if (!sc.ok) return { ok: false, blocked: true, reason: 'out-of-scope SSH host: ' + host };

  const g = enforce(String(command), { confirm: ctx.confirm }, scope);
  if (!g.ok) return { ok: false, blocked: true, reason: g.reason, actionClass: g.actionClass };
  if (g.actionClass === 'lateral') {
    const p = pivotInScope(String(command), scope);
    if (!p.ok) return { ok: false, blocked: true, reason: 'pivot target out of scope', hosts: p.badHosts };
  }
  if (ctx.dryRun) return { ok: true, dryRun: true, host, actionClass: g.actionClass, tier: g.tier };

  if (conn.passFile && !fs.existsSync(conn.passFile))
    return { ok: false, blocked: true, reason: 'passFile not found: ' + conn.passFile };

  const { prefix } = buildArgs(host, conn, String(command));
  const res = (ctx.exec || defaultExec)(prefix);
  audit({ op: 'exec', host, user: conn.user || 'root', command: String(command), actionClass: g.actionClass, status: res.status });

  const ok = res.status === 0;
  if (ok && !known) {
    const id = `ssh-${conn.user || 'root'}@${host}`;
    upsertSession({ id, host, obtained_via: 'ssh', status: 'active', channel: 'ssh', conn: { user: conn.user || 'root', port: conn.port, key: conn.key } }, ctx.sessionsFile);
  }
  return { ok, output: res.stdout, host, actionClass: g.actionClass };
}

// Privesc catalog check BY ID (same contract as sliver.execCheck): text resolved
// from tools/privesc-catalog.json inside this function, never freeform. Requires
// an existing active ssh session (checks are post-breach recon, not brute force).
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
  const known = resolveSession(sessionId, ctx.sessionsFile);
  if (!known || known.status !== 'active')
    return { ok: false, blocked: true, reason: 'no active ssh session: ' + sessionId };
  return exec(known.id, entry.cmds[ctx.index || 0], ctx);
}

module.exports = { exec, execCheck, buildArgs, resolveSession, auditFile };

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
if (require.main === module) {
  const args = process.argv.slice(2);
  const opt = {};
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--user') opt.user = args[++i];
    else if (args[i] === '--port') opt.port = args[++i];
    else if (args[i] === '--key') opt.key = args[++i];
    else if (args[i] === '--pass-file') opt.passFile = args[++i];
    else if (args[i] === '--confirm') opt.confirm = args[++i];
    else if (args[i] === '--dry-run') opt.dryRun = true;
    else pos.push(args[i]);
  }
  const [op, host, command] = pos;
  if (op !== 'exec' || !host || !command) {
    console.log(`usage:
  node tools/sshx.js exec <host|session-id> "<command>" [--user root] [--port N] [--key <idfile>] [--pass-file <f>] [--confirm "<reason>"] [--dry-run]

Every destination host must be in scope.json allowed_hosts/allowed_ips; every command is
tier-classified by c2-guard (confirm-tier needs --confirm with your in-session approval).
A successful connection registers session "ssh-<user>@<host>" in reports/sessions.json.`);
    process.exit(2);
  }
  const r = exec(host, command, opt);
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}
