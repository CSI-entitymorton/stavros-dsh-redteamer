#!/usr/bin/env node
// Bundle secret/endpoint miner (zero-dep). The harness's best finding source, made deterministic.
//   node tools/analyze-bundle.js <url|localfile>
// URL fetches are scope-guarded (DNS/IP-pinned). Extracts JWTs (decoded), Supabase projects,
// common secret patterns, endpoint paths — and FOLLOWS sourceMappingURL references to pull
// sourcesContent out of the .map files (reconstructed source is where the richest secrets live).
const http = require('http');
const https = require('https');
const fs = require('fs');
const { loadScope, inScope } = require('./scope-guard');
const { resolveAndGuard } = require('./net');

// A redirect must land back in scope, or the whole point of the guard is gone.
function resolveRedirect(location, base, scope) {
  const next = new URL(location, base).toString();
  if (!inScope(next, scope).ok) throw new Error('redirect to out-of-scope host blocked: ' + next);
  return next;
}

async function fetch(url, scope) {
  const pin = await resolveAndGuard(url, scope);
  if (pin.blocked) throw new Error(pin.reason);
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? https : http;
    lib
      .get(url, { lookup: (h, o, cb) => cb(null, [{ address: pin.address, family: pin.family }]) }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          let next;
          try {
            next = resolveRedirect(res.headers.location, url, scope);
          } catch (e) {
            return reject(e);
          }
          return resolve(fetch(next, scope));
        }
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => resolve(d));
      })
      .on('error', reject);
  });
}

function b64urlJson(seg) {
  try {
    return JSON.parse(Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function uniq(arr) {
  return [...new Set(arr)];
}

function analyze(text) {
  const out = { jwts: [], supabase_projects: [], secrets: [], sourcemaps: [], endpoints: [] };

  for (const j of text.match(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+)?/g) || []) {
    const p = b64urlJson(j.split('.')[1]);
    if (p)
      out.jwts.push({
        role: p.role || null,
        ref: p.ref || null,
        iss: p.iss || null,
        exp: p.exp || null,
        preview: j.slice(0, 24) + '...',
      });
  }
  out.jwts = uniq(out.jwts.map((x) => JSON.stringify(x))).map((s) => JSON.parse(s));

  out.supabase_projects = uniq((text.match(/https:\/\/[a-z0-9]{20}\.supabase\.co/g) || []).map((s) => s));

  const patterns = [
    ['aws_access_key', /AKIA[0-9A-Z]{16}/g],
    ['google_api_key', /AIza[0-9A-Za-z_-]{35}/g],
    ['stripe_live', /sk_live_[0-9A-Za-z]{16,}/g],
    ['github_pat', /ghp_[0-9A-Za-z]{36}/g],
    ['slack_token', /xox[baprs]-[0-9A-Za-z-]{10,}/g],
    ['sentry_dsn', /https:\/\/[0-9a-f]+@o?[0-9]*\.ingest\.[a-z.]*sentry\.io\/[0-9]+/g],
    ['private_key', /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g],
    // generic "key/secret/token/password: 'value'" assignments with a non-trivial value
    ['generic_assignment', /["'`]?(?:api[_-]?key|secret|token|password|auth[_-]?key|apikey)["'`]?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi],
  ];
  for (const [type, re] of patterns) {
    for (const m of text.matchAll(re)) {
      const val = m[1] || m[0];
      out.secrets.push({ type, value_preview: val.length > 12 ? val.slice(0, 6) + '…' + val.slice(-4) : val });
    }
  }
  out.secrets = uniq(out.secrets.map((x) => JSON.stringify(x))).map((s) => JSON.parse(s));

  out.sourcemaps = uniq((text.match(/sourceMappingURL=([^\s*]+)/g) || []).map((s) => s.replace('sourceMappingURL=', '')));

  const eps = [];
  for (const m of text.matchAll(/["'`](\/(?:api|rest|functions|v[0-9])\/[A-Za-z0-9_\/.-]{1,80})["'`]/g)) eps.push(m[1]);
  for (const m of text.matchAll(/["'`](\/[A-Za-z0-9_-]{2,40}(?:\/[A-Za-z0-9_:{}-]{1,40}){0,5})["'`]/g)) eps.push(m[1]);
  out.endpoints = uniq(eps).slice(0, 200);

  return out;
}

// Follow sourceMappingURL refs, pull sourcesContent out of each .map (scope-guarded, depth-limited),
// and return the reconstructed texts + the list of map URLs. Recurses into nested maps.
async function mineSourcemaps(text, baseUrl, scope, depth) {
  const seen = new Set();
  const texts = [text];
  const maps = [];

  async function walk(srcText, base, d) {
    if (d > 3) return;
    const re = /sourceMappingURL=([^\s*]+)/g;
    let m;
    while ((m = re.exec(srcText))) {
      let mapUrl;
      try {
        mapUrl = new URL(m[1], base).toString();
      } catch {
        continue;
      }
      if (seen.has(mapUrl)) continue;
      seen.add(mapUrl);
      if (!inScope(mapUrl, scope).ok) continue; // never fetch an out-of-scope map
      let mapText;
      try {
        mapText = await fetch(mapUrl, scope);
      } catch {
        continue;
      }
      let parsed;
      try {
        parsed = JSON.parse(mapText);
      } catch {
        continue;
      }
      maps.push(mapUrl);
      const sources = parsed.sources || [];
      const contents = parsed.sourcesContent || [];
      for (let i = 0; i < sources.length; i++) {
        if (typeof contents[i] === 'string' && contents[i]) {
          texts.push(contents[i]);
          await walk(contents[i], mapUrl, d + 1);
        }
      }
    }
  }

  await walk(text, baseUrl, 0);
  return { texts, maps };
}

async function main() {
  const target = process.argv[2];
  if (!target) {
    console.error('usage: node analyze-bundle.js <url|localfile>');
    process.exit(2);
  }
  let text;
  const meta = { sourcemap_count: 0, sourcemap_files: [], sourcemap_sources: 0 };
  if (/^https?:\/\//i.test(target)) {
    const scope = loadScope();
    const r = inScope(target, scope);
    if (!r.ok) {
      console.error(JSON.stringify({ blocked: target, reason: r.reason }));
      process.exit(1);
    }
    try {
      text = await fetch(target, scope);
      const mined = await mineSourcemaps(text, target, scope, 0);
      meta.sourcemap_count = mined.maps.length;
      meta.sourcemap_files = mined.maps;
      meta.sourcemap_sources = mined.texts.length - 1;
      text = mined.texts.join('\n');
    } catch (e) {
      console.error(JSON.stringify({ blocked: target, reason: e.message }));
      process.exit(1);
    }
  } else {
    text = fs.readFileSync(target, 'utf8');
  }
  console.log(require('./privacy').tokenize(JSON.stringify({ source: target, bytes: text.length, ...meta, ...analyze(text) }, null, 2)));
}

if (require.main === module) main();
module.exports = { analyze, resolveRedirect, mineSourcemaps };
