#!/usr/bin/env node
// test-authn-depth.js — self-tests for the P1 authn-depth modules:
//   jwt.js        -> crack (word / derived / self-derived secrets), forge --jwk-self/--jwk-oct,
//                    attack() extra variants (kid traversal, inline jwk)
//   authn-oracle  -> routes classification (open/auth-gated/role-gated/hidden-404),
//                    login clustering (enumeration signal, rate-limit absence), massassign
//   repeater.js   -> --race-watch observed-mutation diffing
// Everything runs against a throwaway local server (127.0.0.1 is in scope.json).
'use strict';

const { spawn } = require('child_process');
const crypto = require('crypto');
const http = require('http');
const path = require('path');

const TOOLS = __dirname;
let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log('PASS  ' + name);
  else { failures++; console.log('FAIL  ' + name + (detail ? ' — ' + detail : '')); }
}

// ---- scenario server ----
// Auth surface deliberately mirrors the bench patterns that got missed:
// hidden authenticated route (404 wall), role gate, enumerable login, merge-echo profile,
// and a stateful redeem/balance pair for race-watch.
const STATE = { balance: 1000 };
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    const auth = (req.headers.authorization || '').replace(/^Bearer /, '');
    const json = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/open') return json(200, { hello: 'world' });
    if (url.pathname === '/private') return auth === 'usertoken' ? json(200, { secret: true }) : json(401, { error: 'unauthorized' });
    if (url.pathname === '/admin-only') return auth === 'admintoken' ? json(200, { admin: true }) : json(403, { error: 'forbidden' });
    if (url.pathname === '/hidden') return json(404, { error: 'not found' });
    if (url.pathname.startsWith('/__control_')) return json(404, { error: 'not found' });
    if (url.pathname === '/login') {
      try {
        const b = JSON.parse(body);
        if (b.username === 'real' && b.password === 'pass123') return json(200, { token: 'usertoken' });
        if (b.username === 'real') return res.writeHead(401, { 'Content-Type': 'application/json' }), res.end(JSON.stringify({ error: 'invalid credentials for the provided account holder entity' }));
        return res.writeHead(401, { 'Content-Type': 'application/json' }), res.end(JSON.stringify({ error: 'no such user' }));
      } catch (e) { return json(400, { error: 'bad json' }); }
    }
    if (url.pathname === '/profile') {
      try {
        const b = JSON.parse(body);
        // Realistic API: accepts and persists a KNOWN subset of fields, silently drops
        // unknown ones — so 'hobby' must NOT look like an accepted mass-assignment sink.
        const merged = Object.assign({ name: 'anon', role: 'user' },
          ...['name', 'role', 'isAdmin'].filter((k) => k in b).map((k) => ({ [k]: b[k] })));
        return json(200, merged);
      } catch (e) { return json(400, { error: 'bad json' }); }
    }
    if (url.pathname === '/balance') return json(200, { balance: STATE.balance });
    if (url.pathname === '/redeem') { STATE.balance -= 1; return json(200, { ok: true }); }
    return json(404, { error: 'not found' });
  });
});

// Async on purpose: this test SERVES the scenario HTTP server from this same process.
// A synchronous execFileSync here would block the event loop, freezing the server while the
// child waits for its responses -> guaranteed 10s timeouts and bogus "indistinguishable"
// classifications. spawn + Promise keeps the loop free while children run.
function nodeRun(args, opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('nodeRun timeout: ' + args.join(' ') + '\nstderr tail: ' + err.slice(-500)));
    }, (opts && opts.timeout) || 120000);
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('exit', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(out);
      else reject(new Error('nodeRun exit ' + code + ': ' + args.join(' ') + '\nstderr tail: ' + err.slice(-800)));
    });
  });
}

async function main() {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;

  // ── jwt.js: crack ──
  const J = require(path.join(TOOLS, 'jwt.js'));
  const enc = J.b64urlEncode;
  const mkTok = (header, payload, key, alg) => {
    const h = enc(JSON.stringify(header)); const p = enc(JSON.stringify(payload));
    return h + '.' + p + '.' + J.sign(h, p, key, alg);
  };
  const c1 = J.crack(mkTok({ alg: 'HS256' }, { sub: '1' }, 's3cr3t', 'HS256'));
  check('crack: embedded common secret found', c1.found && c1.key === 's3cr3t' && c1.derivation === 'word');
  const sha1hex = crypto.createHash('sha1').update('letmein').digest('hex');
  const c2 = J.crack(mkTok({ alg: 'HS256' }, { sub: '2' }, sha1hex, 'HS256'), { words: 'letmein', derive: true });
  check('crack: sha1(seed) derivation found', c2.found && c2.key === sha1hex && c2.derivation === 'sha1(letmein)');
  const h3 = enc(JSON.stringify({ alg: 'HS256' })); const p3 = enc(JSON.stringify({ sub: '3' }));
  const k3 = crypto.createHash('sha1').update(h3 + '.' + p3).digest('hex');
  const c3 = J.crack(h3 + '.' + p3 + '.' + J.sign(h3, p3, k3, 'HS256'), { derive: true });
  check('crack: self-derived sha1(h.p) found', c3.found && c3.key === k3 && c3.derivation === 'self(h.p):sha1');
  const c4 = J.crack(mkTok({ alg: 'HS256' }, { sub: '4' }, 'definitely-not-in-any-list-' + crypto.randomBytes(8).toString('hex'), 'HS256'), { derive: true });
  check('crack: unknown secret reported not-found with attempt count', !c4.found && c4.tried > 400);

  // ── jwt.js: inline-jwk forging ──
  const tokSelf = J.forge(mkTok({ alg: 'RS256' }, { sub: '5' }, '', 'none'), { jwkSelf: true, set: { role: 'admin' } });
  const ps = tokSelf.split('.');
  const hdrS = JSON.parse(Buffer.from(ps[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  const pubKey = crypto.createPublicKey({ key: hdrS.jwk, format: 'jwk' });
  const sigOk = crypto.verify('sha256', Buffer.from(ps[0] + '.' + ps[1]), pubKey,
    Buffer.from(ps[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  const payS = JSON.parse(Buffer.from(ps[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  check('forge --jwk-self: RS256 sig validates against embedded header.jwk, claims kept',
    sigOk && hdrS.jwk.kty === 'RSA' && payS.role === 'admin' && payS.sub === '5');
  const tokOct = J.forge(mkTok({ alg: 'HS256' }, { sub: '6' }, 'oldkey', 'HS256'), { jwkOct: 'newkey', delete: ['sub'] });
  check('forge --jwk-oct: HS256 signed with oct-JWK secret, claim deletes applied',
    J.verify(tokOct, 'newkey').valid && !JSON.parse(Buffer.from(tokOct.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64')).sub);

  // ── authn-oracle routes ──
  const routesFile = path.join(TOOLS, '.test-routes.txt');
  require('fs').writeFileSync(routesFile, '/open\n/private\n/admin-only\n/hidden\n');
  const routes = JSON.parse(await nodeRun([path.join(TOOLS, 'authn-oracle.js'), 'routes', base, '--file', routesFile,
    '--token', 'usertoken', '--admin-token', 'admintoken']));
  const klassOf = (p) => routes.rows.find((r) => r.path === p).klass;
  check('routes: open classified open', klassOf('/open') === 'open', klassOf('/open'));
  check('routes: user-token route classified auth-gated', klassOf('/private') === 'auth-gated', klassOf('/private'));
  check('routes: admin route classified role-gated', klassOf('/admin-only') === 'role-gated', klassOf('/admin-only'));
  check('routes: 404-wall classified hidden-404 (the bench miss)', klassOf('/hidden') === 'hidden-404', klassOf('/hidden'));
  check('routes: calibration says 404 is meaningful', routes.calibration.not_found_meaningful === true);

  // ── authn-oracle login ──
  const login = JSON.parse(await nodeRun([path.join(TOOLS, 'authn-oracle.js'), 'login', base + '/login',
    '--users', 'real,ghost,nobody', '--passwords', 'wrongpass,pass123']));
  check('login: username enumeration flagged (same password splits clusters)',
    Array.isArray(login.verdict.username_enumeration) && login.verdict.username_enumeration.includes('wrongpass'),
    JSON.stringify(login.verdict.username_enumeration));
  check('login: rate-limit absence reported', typeof login.verdict.rate_limit_or_lockout === 'string' && login.verdict.rate_limit_or_lockout.startsWith('absent'),
    JSON.stringify(login.verdict.rate_limit_or_lockout));
  check('login: no false positive on valid creds', login.verdict.valid_credentials === null ||
    (login.verdict.valid_credentials && Object.keys(login.verdict.valid_credentials).length === 1));

  // ── authn-oracle massassign ──
  const ma = JSON.parse(await nodeRun([path.join(TOOLS, 'authn-oracle.js'), 'massassign', base + '/profile',
    '--data', '{"name":"x"}', '--fields', 'role,isAdmin,hobby']));
  check('massassign: accepted fields detected (role, isAdmin), rejected not flagged',
    ma.accepted_candidates.includes('role') && ma.accepted_candidates.includes('isAdmin') && !ma.accepted_candidates.includes('hobby'),
    JSON.stringify(ma.accepted_candidates));
  check('massassign: combined probe changed', ma.combined_probe.changed === true);

  // ── repeater --race-watch ──
  STATE.balance = 1000;
  const out = JSON.parse(await nodeRun([path.join(TOOLS, 'repeater.js'),
    '--url', base + '/redeem', '--method', 'POST', '--race', '5',
    '--race-watch', base + '/balance'], { timeout: 60000 }));
  const w = out[0].watch;
  check('race-watch: mutation observed through state delta (-5)',
    out[0].label === 'race-5-watch' && w.mutated === true && w.deltas.balance === -5,
    JSON.stringify(w.deltas));
  check('race-watch: before/after snapshots captured', w.before.numbers.balance === 1000 && w.after.numbers.balance === 995);
  STATE.balance = 500;
  const out2 = JSON.parse(await nodeRun([path.join(TOOLS, 'repeater.js'),
    '--url', base + '/redeem', '--method', 'POST', '--race', '3',
    '--race-watch', base + '/balance', '--watch-field', 'nonexistent_field'], { timeout: 60000 }));
  check('race-watch: field filter restricts deltas (no false mutation from other numbers)',
    out2[0].watch.mutated === false && Object.keys(out2[0].watch.deltas).length === 0);

  server.close();
  require('fs').rmSync(routesFile, { force: true });

  console.log(failures ? '\n' + failures + ' FAILURES' : '\nALL PASS');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error('test crashed: ' + e.stack); try { server.close(); } catch (x) {} process.exit(2); });
