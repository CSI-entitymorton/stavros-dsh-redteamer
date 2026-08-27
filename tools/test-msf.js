// Self-check: msf.js scope-gates every RHOST BEFORE spawning, and registers opened sessions.
// Run: node tools/test-msf.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
process.env.SESSIONS_JSON = path.join(os.tmpdir(), 'stavros-msf-sess-' + process.pid + '.json');
try { fs.unlinkSync(process.env.SESSIONS_JSON); } catch {}

const M = require('./msf');
const scope = { allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['10.0.0.0/24'] };

// target extraction
assert.deepStrictEqual(M.targetsOf({ RHOSTS: '10.0.0.5' }), ['10.0.0.5']);
assert.deepStrictEqual(M.targetsOf({ RHOST: '10.0.0.7', RPORT: 445 }), ['10.0.0.7']);

// resource script contains the module + options
const rc = M.buildResource('exploit/windows/smb/ms17_010_eternalblue', { RHOSTS: '10.0.0.5', LHOST: '10.0.0.1' });
assert.ok(rc.includes('use exploit/windows/smb/ms17_010_eternalblue'));
assert.ok(rc.includes('set RHOSTS 10.0.0.5'));

// OUT OF SCOPE -> blocked, exec never called
let called = false;
const fakeExec = () => { called = true; return { stdout: '', status: 0 }; };
const outRes = M.runModule('exploit/x', { RHOSTS: '10.0.1.5' }, { exec: fakeExec, scope });
assert.strictEqual(outRes.blocked, true);
assert.strictEqual(called, false, 'exec must NOT run for out-of-scope target');

// IN SCOPE + a session opens in output -> registered
const okExec = () => ({ stdout: 'Meterpreter session 3 opened (10.0.0.1:4444 -> 10.0.0.5:49512)', status: 0 });
const inRes = M.runModule('exploit/x', { RHOSTS: '10.0.0.5', LHOST: '10.0.0.1' }, { exec: okExec, scope });
assert.strictEqual(inRes.ok, true);
assert.deepStrictEqual(inRes.sessions, ['3']);
const S = require('./sessions');
assert.strictEqual(S.loadRegistry().sessions['msf-3'].host, '10.0.0.5');

// e2e (guarded): verify the real msfconsole binary runs the same `-q -x` invocation the
// default exec uses (skipped when Metasploit isn't installed, so the chain stays green elsewhere).
const { spawnSync } = require('child_process');
if (spawnSync('msfconsole', ['--version'], { stdio: 'ignore', timeout: 30000 }).status === 0) {
  const r = spawnSync('msfconsole', ['-q', '-x', 'version; exit -y'], { encoding: 'utf8', timeout: 120000 });
  assert.strictEqual(r.status, 0, 'msfconsole -q -x invocation should exit cleanly');
} else {
  console.log('msf: msfconsole not installed — e2e check skipped');
}

fs.unlinkSync(process.env.SESSIONS_JSON);
console.log('msf: all tests passed');
