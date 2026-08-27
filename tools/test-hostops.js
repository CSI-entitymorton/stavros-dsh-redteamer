// Offline self-check for the host-ops extension: privesc catalog/orchestrator,
// sliver.execCheck (check-by-id), sshx channel gating, and the c2-guard tier
// additions. No binaries are spawned; every exec is a fake. No network.
// Run: node tools/test-hostops.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const G = require('./c2-guard');
const P = require('./privesc');
const sliver = require('./sliver');
const sshx = require('./sshx');

async function main() {

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'hostops-test-'));
const AUDIT = path.join(TMP, 'audit.jsonl');
const SESSIONS = path.join(TMP, 'sessions.json');
const PRIVESC_DIR = path.join(TMP, 'privesc');
process.env.HOSTOPS_AUDIT = AUDIT;
process.env.SESSIONS_JSON = SESSIONS;
process.env.STAVROS_PRIVESC_DIR = PRIVESC_DIR;

const SCOPE = {
  allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['10.0.0.0/24'],
  host_ops: { auto: ['enum', 'loot_read', 'privesc_check'], confirm: ['persist', 'lateral', 'exfil', 'cred_dump', 'privesc_exploit', 'destructive'] },
};

// ---------- c2-guard: new classes / refined lateral ----------
assert.strictEqual(G.classify('sudo -l', SCOPE).actionClass, 'privesc_check');
assert.strictEqual(G.classify('sudo -l', SCOPE).tier, 'auto');
assert.strictEqual(G.classify('sudo -n -l', SCOPE).tier, 'auto');
assert.strictEqual(G.classify('sudo --list', SCOPE).tier, 'auto');
assert.strictEqual(G.classify('getsystem', SCOPE).actionClass, 'privesc_exploit');
assert.strictEqual(G.classify('getsystem', SCOPE).tier, 'confirm');
assert.strictEqual(G.classify('chmod +s /bin/bash', SCOPE).actionClass, 'privesc_exploit');
assert.strictEqual(G.classify('uname -r', SCOPE).actionClass, 'enum');
assert.strictEqual(G.classify('id', SCOPE).actionClass, 'enum');
assert.strictEqual(G.classify('cat /root/.ssh/id_rsa', SCOPE).actionClass, 'loot_read', '.ssh path must NOT be lateral');
assert.strictEqual(G.classify('cat /root/.ssh/id_rsa', SCOPE).tier, 'auto');
assert.strictEqual(G.classify('ssh admin@10.0.0.9', SCOPE).actionClass, 'lateral');
assert.strictEqual(G.classify('scp /tmp/f 10.0.0.9:/tmp/', SCOPE).actionClass, 'lateral');
assert.strictEqual(G.classify('psexec 10.0.0.9', SCOPE).actionClass, 'lateral', 'legacy behavior kept');
// default tiers (no host_ops in scope) must still confirm privesc_exploit
assert.strictEqual(G.classify('getsystem', { allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: [] }).tier, 'confirm');

// ---------- privesc: catalog integrity ----------
const { checks, refs } = P.loadCatalog();
assert.ok(checks.length >= 15, 'catalog has checks for both OS');
assert.ok(checks.every((c) => c.id && c.os && c.title && Array.isArray(c.cmds) && Array.isArray(c.detect)));
assert.ok(new Set(checks.map((c) => c.id)).size === checks.length, 'check ids unique');
assert.ok(P.findRef('lin-chimera').note.includes('chimera-lpe-chain'));
assert.strictEqual(P.findRef('nope'), null);
assert.ok(P.findCheck('win-privs').detect.some((d) => d[1] === 'seimpersonate-potato'));
// every detect triple is [regex, id, severity]
for (const c of checks) for (const d of c.detect) { assert.strictEqual(d.length, 3); new RegExp(d[0]); }

// ---------- privesc: OS detection (auto-safe probes) ----------
const linuxRunner = async (_t, cmd) => cmd.startsWith('cat /etc/os-release') ? { status: 0, output: 'ID=ubuntu\nNAME="Ubuntu"' } : { status: 1, output: '' };
assert.strictEqual(await P.detectOs(linuxRunner, 's1'), 'linux');
const winRunner = async (_t, cmd) => cmd === 'dir C:\\' ? { status: 0, output: 'Volume in drive C has no label.\n Directory of C:\\' } : { status: 1, output: '' };
assert.strictEqual(await P.detectOs(winRunner, 's1'), 'windows');
assert.strictEqual(await P.detectOs(async () => ({ status: 1, output: '' }), 's1'), null);

// ---------- privesc: runChecks (by-ID checks, ranked vectors, transcript+audit) ----------
assert.rejects(() => P.runChecks('s1', {}), /checkRunner/); // fail closed without runner
const outputs = {
  'lin-sudo': { status: 0, output: 'User root may run: NOPASSWD: /usr/bin/su' },
  'lin-suid': { status: 0, output: '/usr/bin/find\n/usr/bin/passwd\n' },
  'lin-caps': { status: 1, output: '' },
  'lin-groups': { status: 0, output: 'uid=1000(op) gid=1000(op) groups=1000(op),999(docker)' },
};
const r = await P.runChecks('sess-1', {
  os: 'linux',
  runner: linuxRunner,
  checkRunner: async (t, id) => outputs[id] || { status: 0, output: '' },
});
assert.strictEqual(r.ok, true);
assert.strictEqual(r.os, 'linux');
assert.strictEqual(r.vectors[0].vector, 'suid-find', 'Critical outranks High');
assert.strictEqual(r.vectors[0].severity, 'Critical');
assert.ok(r.vectors.some((v) => v.vector === 'sudo-nopasswd'));
assert.ok(r.vectors.some((v) => v.vector === 'docker-group-root'));
assert.ok(fs.existsSync(r.transcript), 'transcript written');
const auditLines = fs.readFileSync(AUDIT, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
assert.ok(auditLines.some((a) => a.tool === 'privesc' && a.op === 'check' && a.id === 'lin-suid'));

// ---------- privesc: exploit double gate ----------
const calls = [];
const expRunner = async (t, cmd, ctx) => {
  calls.push({ t, cmd, ctx });
  return { status: 0, output: cmd === 'id' ? 'uid=0(root) gid=0(root)' : 'done' };
};
let e = await P.exploit('sess-1', { cmd: 'chmod +s /bin/bash', ref: 'lin-custom' }, { runner: expRunner, os: 'linux', scope: SCOPE });
assert.strictEqual(e.ok, false);
assert.strictEqual(e.blocked, true);
assert.ok(/--confirm/.test(e.reason), 'refuses without --confirm');
assert.strictEqual(calls.length, 0, 'nothing dispatched before the gate');

e = await P.exploit('sess-1', { cmd: '', ref: 'lin-custom', confirm: 'x' }, { runner: expRunner, os: 'linux' });
assert.strictEqual(e.blocked, true, 'empty command fail closed');

e = await P.exploit('sess-1', { cmd: 'chmod +s /bin/bash', ref: 'lin-custom', confirm: 'operator approved SUID bash for privesc PoC' }, { runner: expRunner, os: 'linux', scope: SCOPE });
assert.strictEqual(e.ok, true);
assert.strictEqual(e.refNote.includes('agent-derived'), true);
assert.strictEqual(calls[0].ctx.confirm, 'operator approved SUID bash for privesc PoC', 'confirm forwarded to channel layer');
assert.strictEqual(e.verified.escalated, true, 'postcheck id shows uid=0');
assert.ok(auditLines.concat(fs.readFileSync(AUDIT, 'utf8').trim().split('\n').map((l) => JSON.parse(l))).length >= 0);
const auditNow = fs.readFileSync(AUDIT, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const expLine = auditNow.find((a) => a.op === 'exploit');
assert.ok(expLine && /SUID bash/.test(expLine.confirmed_by) && expLine.actionClass === 'privesc_exploit');

// ---------- sliver.execCheck: by-ID, session+scope gated, never freeform ----------
const fakeExecSliver = (sid, cmd) => ({ stdout: 'OUT<' + cmd.slice(0, 12) + '>', status: 0 });
let x = sliver.execCheck('ghost', 'lin-sudo', { exec: fakeExecSliver, scope: SCOPE });
assert.strictEqual(x.blocked, true, 'unknown session blocked');
require('./sessions').upsertSession({ id: 'slv-1', host: '10.0.0.5', status: 'active', channel: 'sliver' }, SESSIONS);
x = sliver.execCheck('slv-1', 'lin-sudo', { exec: fakeExecSliver, scope: SCOPE });
assert.strictEqual(x.ok, true);
assert.ok(x.output.startsWith('OUT<sudo -n -l'), 'command text comes from catalog verbatim');
x = sliver.execCheck('slv-1', 'not-a-check', { exec: fakeExecSliver, scope: SCOPE });
assert.strictEqual(x.blocked, true, 'unknown check id blocked');
require('./sessions').upsertSession({ id: 'slv-2', host: '10.9.9.9', status: 'active', channel: 'sliver' }, SESSIONS);
x = sliver.execCheck('slv-2', 'lin-sudo', { exec: fakeExecSliver, scope: SCOPE });
assert.strictEqual(x.blocked, true, 'out-of-scope session host blocked');
// generic runCmd still gates exploit verbs even with a confirm-less caller
const blockedRun = sliver.runCmd('slv-1', 'chmod +s /bin/bash', { exec: fakeExecSliver, scope: SCOPE });
assert.strictEqual(blockedRun.blocked, true);

// ---------- sshx: argv hygiene + gates + registration ----------
const a1 = sshx.buildArgs('10.0.0.5', { user: 'root', key: '/tmp/k' }, 'id');
assert.deepStrictEqual(a1.prefix.slice(0, 3), ['ssh', '-o', 'StrictHostKeyChecking=accept-new']);
assert.ok(a1.prefix.includes('-i') && a1.prefix.includes('/tmp/k'));
assert.ok(a1.prefix.some((s) => s === 'BatchMode=yes'));
const a2 = sshx.buildArgs('10.0.0.5', { user: 'op', port: 2222, passFile: '/tmp/pw' }, 'id');
assert.deepStrictEqual(a2.prefix.slice(0, 2), ['sshpass', '-f'], 'password read from FILE');
assert.ok(a2.prefix.includes('-p') && a2.prefix.includes('2222'));
assert.ok(!JSON.stringify(a2.prefix).includes('secret-value'), 'secret never in argv');
assert.strictEqual(a2.display, '<hidden>id');

let s = sshx.exec('10.9.9.9', 'id', { scope: SCOPE, exec: () => { throw new Error('must not run'); }, sessionsFile: SESSIONS });
assert.strictEqual(s.blocked, true, 'out-of-scope host refused before any spawn');

s = sshx.exec('10.0.0.5', 'chmod +s /bin/bash', { scope: SCOPE, exec: () => { throw new Error('must not run'); }, sessionsFile: SESSIONS });
assert.strictEqual(s.blocked, true, 'confirm-tier refused without --confirm');
s = sshx.exec('10.0.0.5', 'chmod +s /bin/bash', { scope: SCOPE, confirm: 'operator approved', exec: () => ({ status: 0, stdout: 'ok' }), sessionsFile: SESSIONS });
assert.strictEqual(s.ok, true, 'confirm-tier runs with --confirm');

const seen = [];
s = sshx.exec('10.0.0.5', 'id', { scope: SCOPE, exec: (args) => { seen.push(args); return { status: 0, stdout: 'uid=0(root)' }; }, sessionsFile: SESSIONS });
assert.strictEqual(s.ok, true);
assert.strictEqual(s.actionClass, 'enum');
assert.strictEqual(seen.length, 1);
const reg = JSON.parse(fs.readFileSync(SESSIONS, 'utf8'));
const sid = 'ssh-root@10.0.0.5';
assert.ok(reg.sessions[sid], 'successful exec registers ssh session');
assert.strictEqual(reg.sessions[sid].channel, 'ssh');
assert.strictEqual(reg.sessions[sid].obtained_via, 'ssh');

s = sshx.exec('10.0.0.5', 'ssh root@10.0.1.9 id', { scope: SCOPE, exec: () => { throw new Error('must not run'); }, sessionsFile: SESSIONS });
assert.strictEqual(s.blocked, true, 'pivot to out-of-scope host blocked');

// ---------- sshx.execCheck: by-ID + active session ----------
x = sshx.execCheck('ssh-root@10.0.0.5', 'lin-sudo', { scope: SCOPE, exec: (args) => ({ status: 0, stdout: 'CATALOG<' + args[args.length - 1] + '>' }), sessionsFile: SESSIONS });
assert.strictEqual(x.ok, true, 'registered active session passes');
assert.ok(x.output.startsWith('CATALOG<sudo'), 'catalog command sent verbatim as last arg');
x = sshx.execCheck('ssh-root@10.0.0.5', 'nope', { scope: SCOPE, exec: () => ({ status: 0, stdout: '' }), sessionsFile: SESSIONS });
assert.strictEqual(x.blocked, true);
x = sshx.execCheck('ssh-nobody@nowhere', 'lin-sudo', { scope: SCOPE, exec: () => ({ status: 0, stdout: '' }), sessionsFile: SESSIONS });
assert.strictEqual(x.blocked, true, 'no session -> no checks');

// cleanup temp
fs.rmSync(TMP, { recursive: true, force: true });
console.log('hostops: all tests passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
