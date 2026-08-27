#!/usr/bin/env node
// Mint a fresh auth token from credentials, so auth.json can hold email/password instead of a
// token that expires mid-run. Two flows:
//   supabase: POST <url>/auth/v1/token?grant_type=password  (standard Supabase GoTrue)
//   post:     POST an arbitrary login endpoint, extract token via a dotted json path
// The login URL is scope-guarded like everything else.
//   CLI: node tools/login.js <identity>   -> prints the minted token
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { loadScope, inScope } = require('./scope-guard');

function buildLoginRequest(spec) {
  if (spec.type === 'supabase') {
    const base = spec.url.replace(/\/$/, '');
    return {
      url: base + '/auth/v1/token?grant_type=password',
      method: 'POST',
      headers: { apikey: spec.anon_key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: spec.email, password: spec.password }),
    };
  }
  if (spec.type === 'post') {
    return {
      url: spec.url,
      method: spec.method || 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, spec.headers || {}),
      body: typeof spec.body === 'string' ? spec.body : JSON.stringify(spec.body || {}),
    };
  }
  throw new Error('unknown login type: ' + spec.type + " (use 'supabase' or 'post')");
}

function getPath(obj, dotted) {
  return dotted.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function extractToken(spec, json) {
  if (spec.type === 'supabase') return json.access_token;
  return getPath(json, spec.token_path || 'access_token');
}

function request({ url, method, headers, body }) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.request(new URL(url), { method, headers }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function mintToken(spec) {
  const rq = buildLoginRequest(spec);
  const g = inScope(rq.url, loadScope());
  if (!g.ok) throw new Error('login url out of scope: ' + g.reason);
  const resp = await request(rq);
  let json;
  try {
    json = JSON.parse(resp.body);
  } catch {
    throw new Error('login response not JSON (status ' + resp.status + ')');
  }
  const tok = extractToken(spec, json);
  if (!tok) throw new Error('no token in login response (status ' + resp.status + '): ' + resp.body.slice(0, 200));
  return tok;
}

module.exports = { buildLoginRequest, extractToken, getPath, mintToken };

if (require.main === module) {
  const name = process.argv[2];
  if (!name) {
    console.error('usage: node login.js <identity>');
    process.exit(2);
  }
  const p = path.join(__dirname, '..', 'auth.json');
  const auth = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : { identities: {} };
  const id = (auth.identities || {})[name];
  if (!id || !id.login) {
    console.error(`identity '${name}' has no 'login' block in auth.json`);
    process.exit(2);
  }
  mintToken(id.login)
    .then((t) => console.log(t))
    .catch((e) => {
      console.error(String(e.message || e));
      process.exit(1);
    });
}
