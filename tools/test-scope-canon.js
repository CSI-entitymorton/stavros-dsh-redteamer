#!/usr/bin/env node
// Ondata 1 (SA2) — adversarial suite for the scope-guard extensions:
//   B5  canonTarget()/validatePlan() anti-traversal pre-spawn
//   B10a time_window (deterministic clock via opts.now / SCOPE_NOW)
//   B10b DNS pinning resolve-once (FAKE resolver only — NEVER real DNS here)
//   CLI mono-line JSON contract + functional end-to-end on a temp dual-schema scope
//       {targets:['192.168.0.0/24'], exclusions:['192.168.0.1']} and on THIS workspace's
//       real scope.json (lab stays operational).
// Run: node tools/test-scope-canon.js   (offline, deterministic)
'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  loadScope, inScope, canonTarget, validatePlan, resolvePin, checkPin,
} = require('./scope-guard');

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name}`); }
}
function section(t) { console.log(t); }

const GUARD = path.join(__dirname, 'scope-guard.js');

async function main() {
  // ---------------------------------------------------------------------------
  section('-- B5 canonTarget: adversarial inputs (ALL must be refused or normalized per spec)');
  const adv = [
    ['userinfo trick %2f in "credentials" position', 'https://example.com%2f@evil.com/', false],
    ['plain credentials-in-URL',                     'https://user:pass@example.com/',   false],
    ['backslash authority confusion',                'https://evil.com\\@example.com/',  false],
    ['unresolved dot-segment /../',                  'https://example.com/../admin',     false],
    ['percent-encoded HOST label',                   'https://exampl%65.com/',           false],
    ['encoded CRLF smuggling in path',               'https://example.com/%0d%0aX',      false],
    ['port out of range 99999',                      'http://example.com:99999/',        false],
  ];
  for (const [name, input, expectOk] of adv) {
    const r = canonTarget(input);
    ok(name, r.ok === expectOk && !r.ok && typeof r.reason === 'string');
  }

  // suffix-host lookalike is SYNTACTICALLY valid -> canon passes it, the SCOPE check negates it
  {
    const r = canonTarget('https://example.com.evil.com/');
    const s = inScope(r.ok ? r.canonical : '', { allowed_hosts: ['example.com'] });
    ok('suffix-host example.com.evil.com canon-ok but scope-DENIED', r.ok === true && s.ok === false);
  }
  // percent-encoded dot-segments are traversal too
  ok('%2e%2e dot-segment rejected', canonTarget('https://example.com/%2e%2e/admin').ok === false);
  ok('./ dot-segment rejected', canonTarget('https://example.com/./admin').ok === false);
  ok('raw tab/CRLF rejected', canonTarget('https://ex\nample.com/').ok === false);
  ok('raw space rejected', canonTarget('https://ex ample.com/').ok === false);
  ok('empty host rejected', canonTarget('http:///x').ok === false);
  ok('double scheme rejected', canonTarget('https://http://example.com/').ok === false);
  ok('colon-without-port in authority rejected', canonTarget('https://host:abc/').ok === false);

  // ---------------------------------------------------------------------------
  section('-- B5 canonTarget: normalization (must CLEAN, not refuse)');
  {
    ok('trailing dot + uppercase normalized',
       canonTarget('https://EXAMPLE.com./x').canonical === 'https://example.com/x');
    ok('bare host gets http:// scheme',
       canonTarget('EXAMPLE.com').canonical === 'http://example.com/' &&
       canonTarget('EXAMPLE.com').host === 'example.com');
    ok('default port dropped',
       canonTarget('http://example.com:80/x').canonical === 'http://example.com/x' &&
       canonTarget('https://example.com:443').canonical === 'https://example.com/');
    ok('fragment stripped', canonTarget('https://example.com/a/b#frag').canonical === 'https://example.com/a/b');
    ok('non-default port kept', canonTarget('http://example.com:8080/x').canonical === 'http://example.com:8080/x');
    const idna = canonTarget('https://bücher.example/');
    ok('IDNA label converted cleanly', idna.ok === true && idna.host === 'xn--bcher-kva.example' &&
                                       idna.canonical === 'https://xn--bcher-kva.example/');
    ok('punycode xn-- accepted as-is', canonTarget('https://xn--bcher-kva.example/').host === 'xn--bcher-kva.example');
    ok('IPv6 bracket minimal support', (() => {
      const v6 = canonTarget('http://[::1]:8080/x');
      return v6.ok === true && v6.host === '::1' && v6.canonical === 'http://[::1]:8080/x';
    })());
    ok('IPv4 literal target', canonTarget('192.168.0.94').ok === true &&
                              canonTarget('192.168.0.94').host === '192.168.0.94');
  }

  // ---------------------------------------------------------------------------
  section('-- B5 validatePlan: fail-closed compile_plan');
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-canon-'));
    const scopeFile = path.join(dir, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({ targets: ['192.168.0.0/24'], exclusions: ['192.168.0.1'] }));
    const scope = loadScope(scopeFile);

    let r = validatePlan({ targets: ['192.168.0.5', 'http://192.168.0.200/app'] }, { scope });
    ok('all-good plan ok=true', r.ok === true && r.results.length === 2 && r.results.every((x) => x.ok));

    r = validatePlan({ targets: ['192.168.0.5', '10.9.9.9'] }, { scope });
    ok('ONE out-of-scope target -> ok=false (spec case)',
       r.ok === false && r.results[0].ok === true && r.results[1].ok === false);

    r = validatePlan({ targets: ['https://user:pass@example.com/'] }, { scope });
    ok('plan element failing canon -> ok=false', r.ok === false && /userinfo/.test(r.results[0].reason));

    r = validatePlan({ targets: [] }, { scope });
    ok('no targets -> fail closed', r.ok === false);

    r = validatePlan(null, { scope });
    ok('malformed plan -> fail closed', r.ok === false);

    r = validatePlan({ targets: ['192.168.0.5'], commands: ['nmap -sV 192.168.0.7', 'curl http://192.168.0.9/x'] }, { scope });
    ok('commands with in-scope hosts ok=true', r.ok === true && r.results.length === 3 &&
       r.results.filter((x) => x.kind === 'command').every((x) => x.ok));

    r = validatePlan({ targets: ['192.168.0.5'], commands: ['curl https://evil.test/'] }, { scope });
    ok('command host out-of-scope -> ok=false', r.ok === false &&
       r.results.some((x) => x.kind === 'command' && x.ok === false));

    r = validatePlan({ targets: ['192.168.0.5'], commands: ['ls -la'] }, { scope });
    ok('command without any host -> fail closed', r.ok === false &&
       /no target host found/.test(r.results.find((x) => x.kind === 'command').reason));

    // exclusion bites inside plans too (target AND command-host)
    r = validatePlan({ targets: ['192.168.0.1'], commands: ['nmap -p 80 192.168.0.1'] }, { scope });
    ok('excluded address denied both as target and command host', r.ok === false &&
       r.results.length > 0 && r.results.every((x) => x.ok === false));
  }

  // ---------------------------------------------------------------------------
  section('-- B10b resolvePin/checkPin: fake resolver ONLY (never real DNS)');
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-pin-'));
    const pinsFile = path.join(dir, 'dns-pins.json');
    const divLog = path.join(dir, 'dns-divergence.log');
    const fake = (ip) => async () => ip;

    let r = await resolvePin('app.lab.test', { resolver: fake('203.0.113.10'), pinsFile, divergenceLog: divLog });
    ok('first sight pins the address', r.ok === true && r.pinned === '203.0.113.10' && !!r.first_seen);
    let pins = JSON.parse(fs.readFileSync(pinsFile, 'utf8'));
    ok('pins file written atomically {ip,first_seen}',
       pins['app.lab.test'] && pins['app.lab.test'].ip === '203.0.113.10' && !!pins['app.lab.test'].first_seen);

    r = await resolvePin('app.lab.test', { resolver: fake('203.0.113.10'), pinsFile, divergenceLog: divLog });
    ok('same IP on later view -> ok, first_seen immutable',
       r.ok === true && r.first_seen === pins['app.lab.test'].first_seen);

    r = await resolvePin('app.lab.test', { resolver: fake('203.0.113.99'), pinsFile, divergenceLog: divLog });
    ok('diverging IP -> DENIED dns-pin-divergence (spec case)',
       r.ok === false && r.reason === 'dns-pin-divergence' &&
       r.pinned === '203.0.113.10' && r.resolved === '203.0.113.99');
    const lines = fs.readFileSync(divLog, 'utf8').trim().split('\n');
    ok('divergence appended to log', lines.length === 1 &&
       JSON.parse(lines[0]).resolved === '203.0.113.99');

    // pure comparator
    ok('checkPin pure: no prior pin', checkPin('h.t', '1.2.3.4', {}).ok === true);
    ok('checkPin pure: match', checkPin('h.t', '1.2.3.4', { 'h.t': { ip: '1.2.3.4' } }).ok === true);
    const cp = checkPin('h.t', '5.6.7.8', { 'h.t': { ip: '1.2.3.4' } });
    ok('checkPin pure: divergence', cp.ok === false && cp.reason === 'dns-pin-divergence' &&
                                    cp.pinned === '1.2.3.4' && cp.resolved === '5.6.7.8');

    // IP literals never consult DNS: resolver that throws proves it is not called
    r = await resolvePin('127.0.0.1', { resolver: async () => { throw new Error('DNS MUST NOT BE CALLED'); } });
    ok('IP literal skips DNS entirely', r.ok === true && /literal/.test(r.note || ''));

    // resolver failure fails CLOSED
    r = await resolvePin('fail.lab.test', { resolver: async () => { throw new Error('servfail'); } });
    ok('resolver failure -> fail closed', r.ok === false && /resolve failed/.test(r.reason));
  }

  // ---------------------------------------------------------------------------
  section('-- CLI mono-line JSON + functional E2E (temp dual-schema scope + real workspace lab)');
  function cli(args, extraEnv) {
    const env = Object.assign({}, process.env);
    if (extraEnv) for (const [k, v] of Object.entries(extraEnv)) env[k] = v;
    else { delete env.SCOPE_JSON; delete env.SCOPE_NOW; }
    if (!extraEnv || !extraEnv.SCOPE_NOW) delete env.SCOPE_NOW;
    if (!extraEnv || !extraEnv.SCOPE_JSON) delete env.SCOPE_JSON;
    const r = spawnSync(process.execPath, [GUARD, ...args], { encoding: 'utf8', env });
    return { code: r.status, out: r.stdout, err: r.stderr };
  }
  function cliJson(args, extraEnv) {
    const r = cli(args, extraEnv);
    const trimmed = r.out.replace(/\n$/, ''); // console.log appends ONE trailing newline
    assert.strictEqual(trimmed.includes('\n'), false, `mono-line JSON expected, got: ${JSON.stringify(r.out)}`);
    return { ...r, json: JSON.parse(trimmed) };
  }
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-e2e-'));
    const scopeFile = path.join(dir, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({
      project: 'enum-lab-temp', targets: ['192.168.0.0/24'], exclusions: ['192.168.0.1'],
    }));

    let r = cliJson(['check', '192.168.0.5'], { SCOPE_JSON: scopeFile });
    ok('E2E check 192.168.0.5 ALLOW (exit 0)', r.code === 0 && r.json.ok === true);

    r = cliJson(['check', '192.168.0.1'], { SCOPE_JSON: scopeFile });
    ok('E2E check 192.168.0.1 DENY (exclusion)', r.code === 1 && r.json.ok === false && /excluded/.test(r.json.reason));

    r = cliJson(['check', '10.0.0.5'], { SCOPE_JSON: scopeFile });
    ok('E2E check 10.0.0.5 DENY (out of scope)', r.code === 1 && r.json.ok === false);

    const badPlan = path.join(dir, 'plan-mixed.json');
    fs.writeFileSync(badPlan, JSON.stringify({
      targets: ['192.168.0.5', 'http://192.168.0.9/app'],
      commands: ['nmap -sn 192.168.0.7', 'curl http://10.9.9.9/'],
    }));
    r = cliJson(['plan-check', badPlan], { SCOPE_JSON: scopeFile });
    ok('E2E plan-check mixed -> ok=false exit 1', r.code === 1 && r.json.ok === false &&
       r.json.results.filter((x) => !x.ok).length === 1);

    const goodPlan = path.join(dir, 'plan-good.json');
    fs.writeFileSync(goodPlan, JSON.stringify({ targets: ['192.168.0.16/28'], commands: [] }));
    r = cliJson(['plan-check', goodPlan], { SCOPE_JSON: scopeFile });
    ok('E2E plan-check clean -> ok=true exit 0', r.code === 0 && r.json.ok === true);

    r = cliJson(['canon', 'https://user:pass@x.test/'], {});
    ok('E2E canon credentials-in-URL -> exit 1', r.code === 1 && /userinfo/.test(r.json.reason));

    // deterministic time_window through env SCOPE_NOW (CLI inherits the injected clock)
    const windowed = path.join(dir, 'scope-window.json');
    fs.writeFileSync(windowed, JSON.stringify({
      targets: ['192.168.0.0/24'],
      time_window: { start: '2026-01-01T00:00:00Z', end: '2026-02-01T00:00:00Z' },
    }));
    r = cliJson(['check', '192.168.0.5'], { SCOPE_JSON: windowed, SCOPE_NOW: '2026-06-01T00:00:00Z' });
    ok('E2E expired time_window -> deny (spec case)', r.code === 1 &&
       r.json.reason === 'outside engagement time_window');
    r = cliJson(['check', '192.168.0.5'], { SCOPE_JSON: windowed, SCOPE_NOW: '2026-01-15T00:00:00Z' });
    ok('E2E inside time_window -> allow', r.code === 0 && r.json.ok === true);

    // usage errors stay exit 2
    ok('CLI usage error -> exit 2', spawnSync(process.execPath, [GUARD], { encoding: 'utf8' }).status === 2);
    ok('CLI unknown verb -> exit 2', spawnSync(process.execPath, [GUARD, 'frobnicate', 'x'], { encoding: 'utf8' }).status === 2);

    // hermetic fixture emulating the local (project/targets) scope schema: in-scope ALLOW,
    // out-of-scope DENY — never reads the live workspace scope.json (which is an engagement file)
    const fixture = path.join(dir, 'scope-lab.json');
    fs.writeFileSync(fixture, JSON.stringify({
      project: 'lab-fixture', targets: ['192.168.0.94'], exclusions: [],
    }));
    const real = cliJson(['check', 'http://192.168.0.94/'], { SCOPE_JSON: fixture });
    ok('fixture scope.json: check http://192.168.0.94/ ALLOW (in-scope)',
       real.code === 0 && real.json.ok === true);
    const realDeny = cliJson(['check', 'http://172.16.5.5/'], { SCOPE_JSON: fixture });
    ok('fixture scope.json: out-of-scope still denied', realDeny.code === 1 && realDeny.json.ok === false);
  }

  console.log(`\nscope-canon: ${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
