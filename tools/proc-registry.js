#!/usr/bin/env node
// E9 (rimandati) — process registry per scan lunghe: task-id/pause/status/terminate SENZA kill.
//
// Registry (JSON atomico tmp+rename): env PROC_REGISTRY_FILE o <ws>/reports/tmp/proc-registry.json
//   { tasks: { <task_id>: { task_id, pid, bin, args, started_at, status: running|paused|exited|terminated, via } } }
//
// Semantica di sicurezza (fail-closed):
//   - I segnali si applicano SOLO a pid registrati dal harness (lookup per task_id): mai pid
//     arbitrari, mai pid non in registry (exit 2 con messaggio chiaro).
//   - pause = SIGSTOP (sospende, NON uccide) · resume = SIGCONT · terminate = SIGTERM (graceful,
//     MAI SIGKILL). Nessuna primitiva di kill forzata.
//   - Un pid morto (ESRCH) → stato aggiornato a exited, mai errore silenzioso.
//
// Hook run.js: `--task-id <id>` registra il figlio spawnato a spawn-time (così un altro processo
// può fare pause/terminate a scan in corso) e lo marca exited alla chiusura.
//
// CLI:
//   node tools/proc-registry.js register --task-id X --pid N --bin B [--args ...] [--via ...]
//   node tools/proc-registry.js status [--task-id X] [--json]
//   node tools/proc-registry.js pause --task-id X
//   node tools/proc-registry.js resume --task-id X
//   node tools/proc-registry.js terminate --task-id X
//   node tools/proc-registry.js list
'use strict';
const fs = require('fs');
const path = require('path');

const REGISTRY_FILE = () => process.env.PROC_REGISTRY_FILE ||
  path.join(__dirname, '..', 'reports', 'tmp', 'proc-registry.json');

function load() {
  try { return JSON.parse(fs.readFileSync(REGISTRY_FILE(), 'utf8')); } catch { return { tasks: {} }; }
}

function save(st) {
  fs.mkdirSync(path.dirname(REGISTRY_FILE()), { recursive: true });
  const tmp = REGISTRY_FILE() + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(st, null, 2) + '\n');
  fs.renameSync(tmp, REGISTRY_FILE());
}

function nowIso() { return new Date().toISOString(); }

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return false; }
}

function mutex(taskId, fn) {
  const st = load();
  const task = st.tasks[taskId];
  if (!task) return { ok: false, error: `unknown task_id "${taskId}" (registrato solo da run.js --task-id o register)` };
  if (!alive(task.pid)) {
    task.status = 'exited';
    task.exited_at = nowIso();
    save(st);
    return { ok: false, error: `task ${taskId} (pid ${task.pid}) not running anymore (status -> exited)` };
  }
  fn(task);
  save(st);
  return { ok: true, task };
}

function register({ taskId, pid, bin, args, via }) {
  if (!taskId || !pid || !Number.isInteger(pid) || pid <= 0) return { ok: false, usage: true };
  const st = load();
  if (st.tasks[taskId]) return { ok: false, error: `task_id "${taskId}" already registered` };
  st.tasks[taskId] = { task_id: taskId, pid, bin: bin || 'unknown', args: args || [], started_at: nowIso(), status: 'running', via: via || 'cli' };
  save(st);
  return { ok: true, task: st.tasks[taskId] };
}

function status(taskId) {
  const st = load();
  if (taskId) {
    const t = st.tasks[taskId];
    if (!t) return { ok: false, error: `unknown task_id "${taskId}"` };
    return { ok: true, task: { ...t, alive: alive(t.pid) } };
  }
  return { ok: true, tasks: Object.values(st.tasks).map((t) => ({ ...t, alive: alive(t.pid) })) };
}

function pause(taskId) {
  return mutex(taskId, (t) => {
    process.kill(t.pid, 'SIGSTOP');
    t.status = 'paused';
    t.paused_at = nowIso();
  });
}

function resume(taskId) {
  return mutex(taskId, (t) => {
    process.kill(t.pid, 'SIGCONT');
    t.status = 'running';
    t.resumed_at = nowIso();
  });
}

// terminate = SIGTERM (graceful shutdown, MAI SIGKILL); il processo può terminare pulito.
function terminate(taskId) {
  return mutex(taskId, (t) => {
    process.kill(t.pid, 'SIGTERM');
    t.status = 'terminated';
    t.terminated_at = nowIso();
  });
}

// run.js hook: marca exited alla chiusura del figlio (mai errore se già uscito).
function markExited(taskId, exitCode) {
  const st = load();
  const t = st.tasks[taskId];
  if (!t) return { ok: false, error: `unknown task_id "${taskId}"` };
  t.status = 'exited';
  t.exit_code = exitCode == null ? null : exitCode;
  t.exited_at = nowIso();
  save(st);
  return { ok: true, task: t };
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
  const has = (n) => argv.includes(n);
  let r;
  if (cmd === 'register') {
    r = register({
      taskId: opt('--task-id'), pid: parseInt(opt('--pid'), 10) || null,
      bin: opt('--bin'), via: opt('--via'), args: argv.slice(argv.indexOf('--args') + 1).filter((a) => a !== '--via'),
    });
    if (r.usage) { console.error('usage: register --task-id X --pid N --bin B [--args ...]'); process.exit(2); }
  } else if (cmd === 'status') {
    r = status(opt('--task-id'));
  } else if (cmd === 'list') {
    r = status(null);
  } else if (cmd === 'pause') {
    r = pause(opt('--task-id'));
  } else if (cmd === 'resume') {
    r = resume(opt('--task-id'));
  } else if (cmd === 'terminate') {
    r = terminate(opt('--task-id'));
  } else {
    console.error('usage: node tools/proc-registry.js register|status|list|pause|resume|terminate [...]');
    process.exit(2);
  }
  const json = has('--json') || cmd === 'status' || cmd === 'list';
  console.log(JSON.stringify(r, null, json ? 2 : 0));
  process.exit(r.ok ? 0 : 1);
}

if (require.main === module) process.exit(main());

module.exports = { register, status, pause, resume, terminate, markExited, load, REGISTRY_FILE };
