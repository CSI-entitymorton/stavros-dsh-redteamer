// Offline self-checks for run.js: streaming execution, --run-timeout, and piped-stdin handling.
// Run: node tools/test-run.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const RUN = path.join(ROOT, 'tools', 'run.js');
const scopeFile = path.join(os.tmpdir(), 'run-scope-' + process.pid + '.json');
fs.writeFileSync(scopeFile, JSON.stringify({
  allowed_hosts: ['example.com'],
  allowed_url_prefixes: [],
  allowed_ips: ['127.0.0.1', '10.0.0.0/8'],
  max_requests_per_second: 100,
}));

function invoke(args, input) {
  return spawnSync(process.execPath, [RUN, ...args], {
    cwd: ROOT,
    env: Object.assign({}, process.env, { SCOPE_JSON: scopeFile }),
    input,
    encoding: 'utf8',
    timeout: 15000,
  });
}

// 1) streaming: child stdout is inherited and reaches our captured stdout; exit code preserved
const r1 = invoke(['node', '-e', 'process.stdout.write("HELLO-STREAM")', '127.0.0.1']);
assert.strictEqual(r1.status, 0, 'exit 0, stderr: ' + r1.stderr);
assert.ok(r1.stdout.includes('HELLO-STREAM'), 'child stdout streamed through: ' + r1.stdout);

// 2) --run-timeout kills a runaway child (non-zero exit, well before its 5s sleep)
const t0 = Date.now();
const r2 = invoke(['--run-timeout', '300', 'node', '-e', 'setTimeout(()=>{}, 5000)', '127.0.0.1']);
assert.notStrictEqual(r2.status, 0, 'timeout -> non-zero exit');
assert.ok(Date.now() - t0 < 5000, 'killed well before the 5s sleep');

// 3) piped stdin with a host list is scope-checked AND forwarded (cat echoes it back)
const r3 = invoke(['cat'], '10.0.0.1\n');
assert.strictEqual(r3.status, 0, 'stdin host in scope -> exit 0, stderr: ' + r3.stderr);
assert.ok(r3.stdout.includes('10.0.0.1'), 'stdin forwarded to child: ' + r3.stdout);

// 4) out-of-scope stdin host is refused (fail closed)
const r4 = invoke(['cat'], '203.0.113.5\n');
assert.strictEqual(r4.status, 1, 'out-of-scope stdin -> blocked');

// 5) h8mail email targets: domain after '@' extracted and scope-checked (--dry-run)
const r5 = invoke(['--dry-run', 'h8mail', '-t', 'user@example.com']);
assert.strictEqual(r5.status, 0, 'in-scope email domain -> dry-run ok: ' + r5.stdout);
assert.ok(r5.stdout.includes('example.com'), 'extracted host visible: ' + r5.stdout);

// 6) out-of-scope email domain is refused (fail closed)
const r6 = invoke(['--dry-run', 'h8mail', '-t', 'user@evil.org']);
assert.strictEqual(r6.status, 1, 'out-of-scope email domain -> blocked');

fs.rmSync(scopeFile, { force: true });
console.log('run: all tests passed');
