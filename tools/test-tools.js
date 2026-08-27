// Offline self-checks for the hardening/analysis tools.
// Run: node tools/test-tools.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { collectHosts, bareHost, hostsFromText } = require('./run');
const { analyze, resolveRedirect } = require('./analyze-bundle');
const { varyRequest, pickSecHeaders } = require('./repeater');
const { validate, key } = require('./record-finding');
const { buildLoginRequest, extractToken, getPath } = require('./login');

// --- run.js host extraction ---
assert.deepStrictEqual(collectHosts(['-u', 'https://a.example.com/x?y=1']), ['a.example.com']);
assert.deepStrictEqual(collectHosts(['target.com']), ['target.com']);
// filenames must NOT be treated as hosts (else legit runs get blocked)
assert.strictEqual(bareHost('swagger.json'), null);
assert.strictEqual(bareHost('reports/tmp/req.txt'), null);
assert.strictEqual(bareHost('example.com'), 'example.com');
// no host in args -> empty (wrapper then fails closed)
assert.deepStrictEqual(collectHosts(['--batch', '--level', '2']), []);
// emails (h8mail -t user@dom): the domain after '@' is the host to scope-check
assert.deepStrictEqual(collectHosts(['h8mail', '-t', 'admin@example.com']), ['example.com']);
assert.deepStrictEqual(collectHosts(['h8mail', '-t', 'a@x.io', 'b@y.io']), ['x.io', 'y.io']);
assert.deepStrictEqual(collectHosts(['-t', 'user@example.com']), ['example.com']);
assert.deepStrictEqual(collectHosts(['h8mail', '-t', 'admin@10.0.0.1']), [], 'no TLD -> no host (fails closed)');
// h8mail -t FILE: the file's emails' domains are scope-checked too (bin-aware list flag)
const h8tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'h8mail-'));
const h8targets = path.join(h8tmp, 'targets.txt');
fs.writeFileSync(h8targets, 'ceo@example.com\nadmin@example.com\n');
assert.deepStrictEqual(collectHosts(['-t', h8targets], null, 'h8mail'), ['example.com']);
fs.rmSync(h8tmp, { recursive: true, force: true });
// network-scanner targets: CIDR ranges + non-http schemes (ldap/smb/...)
assert.strictEqual(bareHost('10.0.0.0/24'), '10.0.0.0/24');
assert.deepStrictEqual(collectHosts(['nmap', '-sV', '10.0.0.0/24']), ['10.0.0.0/24']);
assert.deepStrictEqual(collectHosts(['netexec', 'smb', '192.168.1.0/24']), ['192.168.1.0/24']);
assert.deepStrictEqual(collectHosts(['impacket-GetNPUsers', 'corp/', '-dc-ip', '10.0.0.1']), ['10.0.0.1']);
assert.deepStrictEqual(collectHosts(['ldapsearch', '-H', 'ldap://10.0.0.1']), ['10.0.0.1']);
assert.deepStrictEqual([...hostsFromText('10.0.0.0/24\nldap://10.0.0.1\n')], ['10.0.0.0/24', '10.0.0.1']);
// CIDR-in-scope: target range must be a SUBSET of an authorized CIDR
const { cidrInScope } = require('./scope-guard');
assert.strictEqual(cidrInScope('10.0.0.0/24', { allowed_ips: ['10.0.0.0/8'] }).ok, true);
assert.strictEqual(cidrInScope('10.0.0.0/24', { allowed_ips: ['10.1.0.0/16'] }).ok, false);
assert.strictEqual(cidrInScope('10.0.0.0/8', { allowed_ips: ['10.0.0.0/24'] }).ok, false); // superset not allowed
assert.strictEqual(cidrInScope('10.0.0.0/24', { allowed_ips: [] }).ok, false);
// signed-int32 edge: 192.x nets are >= 2^31 (negative as int32) — must still match
assert.strictEqual(cidrInScope('192.168.3.0/24', { allowed_ips: ['192.168.3.0/24'] }).ok, true);
assert.strictEqual(cidrInScope('192.168.3.5', { allowed_ips: ['192.168.3.0/24'] }).ok, true); // /32 within CIDR
assert.strictEqual(cidrInScope('192.168.4.0/24', { allowed_ips: ['192.168.3.0/24'] }).ok, false);

// --- analyze-bundle secret/jwt detection ---
const svcJwt = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ iss: 'supabase', ref: 'abc', role: 'service_role' })).toString('base64url') + '.sig';
const a = analyze(`const k="${svcJwt}"; url="https://examplesupabaseref00.supabase.co"; apiKey: "example-api-key-value"`);
assert.ok(a.jwts.some((j) => j.role === 'service_role'), 'must decode service_role jwt');
assert.ok(a.supabase_projects.includes('https://examplesupabaseref00.supabase.co'));
assert.ok(a.secrets.some((s) => s.type === 'generic_assignment'), 'must catch hardcoded apiKey');

// --- record-finding validation ---
assert.strictEqual(validate({ severity: 'High', title: 't', host: 'h', poc: 'p' }), null);
assert.ok(validate({ severity: 'Nope', title: 't', host: 'h', poc: 'p' })); // bad severity
assert.ok(validate({ severity: 'High', title: 't', host: 'h' })); // missing poc
assert.strictEqual(key({ host: 'H', endpoint: '/x', title: 'T' }), 'h|/x|t');

// --- login.js request building & token extraction (offline) ---
const sbReq = buildLoginRequest({ type: 'supabase', url: 'https://ref.supabase.co/', anon_key: 'AK', email: 'e@x.io', password: 'p' });
assert.strictEqual(sbReq.url, 'https://ref.supabase.co/auth/v1/token?grant_type=password');
assert.strictEqual(sbReq.headers.apikey, 'AK');
assert.deepStrictEqual(JSON.parse(sbReq.body), { email: 'e@x.io', password: 'p' });
assert.strictEqual(extractToken({ type: 'supabase' }, { access_token: 'TOK' }), 'TOK');
assert.strictEqual(extractToken({ type: 'post', token_path: 'data.token' }, { data: { token: 'X' } }), 'X');
assert.strictEqual(getPath({ a: { b: { c: 1 } } }, 'a.b.c'), 1);
assert.strictEqual(getPath({ a: 1 }, 'a.b.c'), undefined);
assert.throws(() => buildLoginRequest({ type: 'nope' }));

// --- analyze-bundle redirect must stay in scope (fail-closed on every hop) ---
const scope = { allowed_hosts: ['example.com'] };
assert.strictEqual(resolveRedirect('/x', 'https://example.com/', scope), 'https://example.com/x');
assert.strictEqual(resolveRedirect('https://api.example.com/y', 'https://example.com/', scope), 'https://api.example.com/y');
assert.throws(() => resolveRedirect('https://evil.com/', 'https://example.com/', scope), /out-of-scope/);
assert.throws(() => resolveRedirect('//evil.com/', 'https://example.com/', scope), /out-of-scope/); // protocol-relative

// --- repeater --vary: query param, FUZZ in path, FUZZ in body ---
assert.deepStrictEqual(varyRequest('https://h/api/Order/FUZZ', null, 'id', '7'), { url: 'https://h/api/Order/7', data: null });
assert.deepStrictEqual(varyRequest('https://h/x?a=1', null, 'id', '7'), { url: 'https://h/x?a=1&id=7', data: null });
// FUZZ in body only: url untouched, body substituted (no stray query param)
assert.deepStrictEqual(varyRequest('https://h/order', '{"id":"FUZZ"}', 'id', '9'), { url: 'https://h/order', data: '{"id":"9"}' });

// --- repeater security-header picking (F7/F8 evidence) ---
const sec = pickSecHeaders({ 'content-security-policy': "default-src 'self'", 'x-powered-by': 'noise', server: 'nginx' });
assert.deepStrictEqual(sec, { 'content-security-policy': "default-src 'self'", server: 'nginx' });
assert.deepStrictEqual(pickSecHeaders({}), {}); // nothing present -> empty (signals missing headers)

// --- repeater: vars, multipart, similarity, cookie jar (new engine) ---
const { applyVars, buildMultipart, similarity, cookieHeader, absorbSetCookies } = require('./repeater');
assert.strictEqual(applyVars('https://h/x?id={{tok}}', { tok: 'ABC' }), 'https://h/x?id=ABC');
assert.strictEqual(applyVars('https://h/x?id={{missing}}', { tok: 'ABC' }), 'https://h/x?id={{missing}}'); // unknown var left alone
const mp = buildMultipart({ note: 'hi' }, [['file', __filename]]);
assert.ok(mp.contentType.startsWith('multipart/form-data; boundary='));
assert.ok(mp.body.toString('latin1').includes('name="file"; filename="test-tools.js"'));
assert.ok(mp.body.toString('latin1').includes('name="note"'));
assert.strictEqual(similarity('a b c d', 'a b c d'), 1);
assert.strictEqual(similarity('a b c d', 'a b c x'), 0.75);
assert.strictEqual(similarity('a b', ''), 0);
const jar = { cookies: {}, vars: {} };
absorbSetCookies(jar, 'h.com', ['sid=1; Path=/', 'sid=2; Path=/', 'other=9; HttpOnly']); // same name replaced
assert.strictEqual(cookieHeader('h.com', jar), 'sid=2; other=9');
assert.strictEqual(cookieHeader('other.com', jar), '');

// --- jwt: decode/verify/forge ---
const { decode, verify, forge, sign, b64urlEncode } = require('./jwt');
const jwtTok = b64urlEncode(JSON.stringify({ alg: 'HS256' })) + '.' +
  b64urlEncode(JSON.stringify({ sub: 'u1', role: 'user', exp: 9999999999 })) + '.' + 'sig';
assert.strictEqual(decode(jwtTok).role, 'user');
assert.strictEqual(decode(jwtTok).alg, 'HS256');
const signed = forge(jwtTok, { alg: 'HS256', key: 's3cret' });
assert.strictEqual(verify(signed, 's3cret').valid, true);
assert.strictEqual(verify(signed, 'wrong').valid, false);
const noneTok = forge(jwtTok, { alg: 'none', set: { role: 'admin' } });
assert.ok(noneTok.endsWith('.'), 'alg:none leaves empty signature');
assert.strictEqual(decode(noneTok).role, 'admin');
assert.throws(() => forge('not-a-jwt', {}));

// --- csp flagging ---
const { flag: flagCsp, parsePolicy } = require('./csp');
assert.deepStrictEqual(parsePolicy("default-src 'self'; script-src 'self' 'unsafe-inline'"), [
  { name: 'default-src', values: ["'self'"] },
  { name: 'script-src', values: ["'self'", "'unsafe-inline'"] },
]);
const weak = flagCsp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; frame-ancestors 'none'").flags;
assert.ok(weak.some((f) => f.issue.includes('unsafe-inline')));
assert.ok(weak.some((f) => f.issue.includes('unsafe-eval')));
assert.ok(flagCsp('').flags[0].issue.includes('No Content-Security-Policy'));
const strict = flagCsp("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests").flags;
assert.strictEqual(strict.length, 0, 'tight policy flags nothing, got: ' + JSON.stringify(strict));

// --- cors verdict ---
const { verdict } = require('./cors');
assert.strictEqual(verdict('https://evil.com', 'https://evil.com', true).severity, 'critical');
assert.strictEqual(verdict('https://evil.com', 'https://evil.com', false).severity, 'medium');
assert.strictEqual(verdict('https://evil.com', '*', false).severity, 'low');
assert.strictEqual(verdict('https://evil.com', '*', true).severity, 'high');
assert.strictEqual(verdict('null', 'null', true).severity, 'high');
assert.strictEqual(verdict('https://evil.com', undefined, false).severity, 'info');

// --- cvss v3.1 calculator (reference values from the spec) ---
const { calculate } = require('./cvss');
assert.strictEqual(calculate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').base_score, 9.8);
assert.strictEqual(calculate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').severity, 'Critical');
assert.strictEqual(calculate('AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N').base_score, 6.5);
assert.strictEqual(calculate('AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H').base_score, 8.8);
assert.strictEqual(calculate('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N').base_score, 3.9); // spec quirk: exploitability alone yields 3.9
assert.throws(() => calculate('AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), /invalid/);
assert.throws(() => calculate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'), /missing metric/);

// --- chain builder ---
const { buildChains, classify } = require('./chain');
assert.strictEqual(classify('IDOR: read any user'), 'authz');
assert.strictEqual(classify('Hardcoded API key in bundle'), 'leak');
const cf = [
  { host: 'api.x', severity: 'Critical', title: 'IDOR token mint for any user', poc: 'x' },
  { host: 'api.x', severity: 'High', title: 'Hardcoded API key in bundle', poc: 'x' },
  { host: 'api.x', severity: 'High', title: 'Missing auth on GetSSOToken (no auth header)', poc: 'x' },
];
const chains = buildChains(cf)[0].chains.map((c) => c.name);
assert.ok(chains.includes('Leaked-secret authorization bypass'));
assert.ok(chains.includes('Unauthenticated impersonation'));
assert.strictEqual(buildChains([{ host: 'a', severity: 'Low', title: 'missing header', poc: 'x' }]).length, 0);

// --- map.js structured handoff ---
const mapjs = require('./map');
assert.strictEqual(mapjs.validate({ host: 'h', path: '/x' }), null);
assert.ok(mapjs.validate({ host: 'h' })); // missing path
assert.ok(mapjs.validate({ host: 'h', path: '/x', candidates: { nope: ['id'] } })); // unknown class
const added = mapjs.add(JSON.stringify({ host: 'test.invalid', path: '/v1/O', method: 'GET', params: ['id'], candidates: { idor: ['id'], sqli: [] } }));
assert.strictEqual(added.ok, true);
const cands = mapjs.candidates('test.invalid').candidates;
assert.ok(cands.idor.some((c) => c.includes('/v1/O')));
assert.ok(cands.other.some((c) => c.includes('params=id')) === false);
const fs2 = require('fs');
fs2.rmSync(require('path').join(__dirname, '..', 'reports', 'test.invalid-map.json'), { force: true });

// --- graphql summarize ---
const { summarize } = require('./graphql');
const fakeSchema = { data: { __schema: { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, subscriptionType: null, types: [
  { name: 'Query', fields: [{ name: 'customers' }] },
  { name: 'Mutation', fields: [{ name: 'createOrder' }] },
  { name: 'Customer', fields: [{ name: 'id' }] },
] } } };
const sum = summarize(fakeSchema);
assert.deepStrictEqual(sum.queries, ['customers']);
assert.deepStrictEqual(sum.mutations, ['createOrder']);
assert.strictEqual(sum.type_count, 3);

// --- run.js: localhost + stdin ---
const { bareHost: bh2 } = require('./run');
assert.strictEqual(bh2('localhost'), 'localhost');
assert.strictEqual(bh2('foo'), null); // other single labels rejected
assert.deepStrictEqual([...hostsFromText('https://a.example.com/x\nother.com\n')], ['a.example.com', 'other.com']);

// --- record-finding extended schema ---
const { validate: validateFinding } = require('./record-finding');
assert.strictEqual(validateFinding({ severity: 'High', title: 't', host: 'h', poc: 'p', cvss: 8.1, cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-200', remediation: 'fix it' }), null);
assert.ok(validateFinding({ severity: 'High', title: 't', host: 'h', poc: 'p', cvss: 11 })); // > 10
assert.ok(validateFinding({ severity: 'High', title: 't', host: 'h', poc: 'p', cvss: 'high' })); // not a number
assert.ok(validateFinding({ severity: 'High', title: 't', host: 'h', poc: 'p', cvss_vector: 'AV:N/AC:L' })); // bad vector

// --- net.js: special-range detection (DNS-rebinding guard) ---
const { specialRange } = require('./net');
assert.strictEqual(specialRange('10.1.2.3'), 'private');
assert.strictEqual(specialRange('172.16.5.5'), 'private');
assert.strictEqual(specialRange('192.168.1.1'), 'private');
assert.strictEqual(specialRange('127.0.0.1'), 'loopback');
assert.strictEqual(specialRange('169.254.169.254'), 'link-local');
assert.strictEqual(specialRange('100.64.0.1'), 'cgnat');
assert.strictEqual(specialRange('8.8.8.8'), null);
assert.strictEqual(specialRange('::1'), 'loopback');
assert.strictEqual(specialRange('::'), 'unspecified');
assert.strictEqual(specialRange('fe80::1'), 'link-local');
assert.strictEqual(specialRange('fd00::1'), 'private');
assert.strictEqual(specialRange('2001:4860:4860::8888'), null);
assert.strictEqual(specialRange('::ffff:169.254.169.254'), 'link-local');

// --- jwt: --set-header injection (kid/jku/x5u) + RS256->HS256 confusion forge ---
const hdrJwt = b64urlEncode(JSON.stringify({ alg: 'RS256', kid: 'old' })) + '.' +
  b64urlEncode(JSON.stringify({ sub: 'u', role: 'user' })) + '.sig';
const confused = forge(hdrJwt, { alg: 'HS256', key: 'pub', setHeader: { kid: 'newkid', jku: 'https://evil/jwks.json' } });
assert.strictEqual(decode(confused).alg, 'HS256');
assert.strictEqual(decode(confused).header.kid, 'newkid');
assert.strictEqual(decode(confused).header.jku, 'https://evil/jwks.json');
// alg:none with an explicit kid must NOT drop the caller's kid
const noneKid = forge(hdrJwt, { alg: 'none', setHeader: { kid: 'kept' } });
assert.strictEqual(decode(noneKid).header.kid, 'kept');
assert.strictEqual(decode(noneKid).alg, 'none');

// --- record-finding: evidence redaction ---
const { redact } = require('./record-finding');
assert.strictEqual(redact('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIjoi'), 'Authorization: Bearer REDACTED');
assert.ok(redact('key=AKIAIOSFODNN7EXAMPLE').includes('AWS_KEY_REDACTED'));
assert.ok(redact('xoxb-123456789012-abcdef').includes('SLACK_TOKEN_REDACTED'));
assert.ok(!redact('just a normal sentence').includes('REDACTED'));

// --- analyze-bundle: sourceMappingURL listing (feeds the .map miner) ---
assert.ok(analyze('const a=1;\n//# sourceMappingURL=app.js.map\n').sourcemaps.includes('app.js.map'));

console.log('tools: all tests passed');
