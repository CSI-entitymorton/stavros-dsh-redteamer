#!/usr/bin/env node
// Zero-dependency HTTP repeater with a HARD scope guard.
// Every request is checked against scope.json IN CODE - the model cannot bypass it.
// Use for precise request tampering: IDOR/BOLA, auth checks, param fuzzing, SSRF probes,
// multi-step authed flows, race conditions, file uploads.
//
// Engine features:
//   --timeout <ms>            request timeout (default 10000); a hang reports {timeout:true}
//   --follow                  follow redirects (<=5 hops), re-checking scope on EVERY hop
//   --session <file>          session state: host-keyed cookie jar + extracted vars
//                             (required for --cookies/--extract)
//   --cookies <file>          alias of --session: load + persist set-cookie per host
//   --extract "name=regex"    capture first match from each response body (or Location)
//                             into session vars (--session required); supports {{name}}
//   --var name=value          set a literal var; {{name}} in --url/--data/--header is replaced
//   --diff                    in --vary mode, also report body_similarity (0..1) vs baseline
//                             (catches same-length-different-content IDOR)
//   --race <n>                fire n identical requests concurrently (TOCTOU/race testing)
//   --upload field=path       multipart file upload (repeatable)
//   --form k=v                extra multipart field (repeatable)
//   --no-pace                 skip the global cross-process rate limiter (use carefully)
//
// Defaults: browser-ish User-Agent, Accept-Encoding: identity (gzip/deflate/br still
// decompressed if a server sends them anyway), global pacing from scope.json.
//
// ponytail: this guard covers ONLY requests sent through this script. Third-party
// binaries (sqlmap/nuclei/ffuf/...) are guarded procedurally (agents must run
// `scope-guard.js check` first). Upgrade path if procedural isn't enough: route all
// tools through a local allowlisting HTTP proxy.
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { URL } = require('url');
const { loadScope, inScope } = require('./scope-guard');
const { wait } = require('./pace');
const { resolveAndGuard } = require('./net');
const ssrfGuard = require('./ssrf-guard'); // B9 second layer (ondata 3)
const privacy = require('./privacy');
const { loadEgressProxy, tlsTunnel } = require('./proxy-route');

const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const DEFAULT_TIMEOUT = 10000;
const MAX_REDIRECTS = 5;
const BODY_CAP = 2048; // enough to confirm a leaked row / error string / reflected payload, small enough for weak models

// ---------------------------------------------------------------------------
// Resolve headers for a named identity from auth.json (for IDOR/BOLA and authed testing).
// An identity has either static `headers`, or a `login` block that mints a fresh token
// from credentials (survives token expiry mid-run).
async function resolveIdentity(name) {
  if (!name) return [];
  const p = path.join(__dirname, '..', 'auth.json');
  const auth = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : { identities: {} };
  const id = (auth.identities || {})[name];
  if (!id) {
    console.error(JSON.stringify({ error: `identity '${name}' not found in auth.json` }));
    process.exit(2);
  }
  if (id.login) {
    try {
      const token = await require('./login').mintToken(id.login);
      return ['Authorization: Bearer ' + token, ...(id.extra_headers || [])];
    } catch (e) {
      console.error(JSON.stringify({ error: 'login failed for ' + name + ': ' + (e.message || e) }));
      process.exit(2);
    }
  }
  return id.headers || [];
}

// ---------------------------------------------------------------------------
// Session state: { cookies: { host: [rawSetCookie...] }, vars: { name: value } }
function loadSession(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return { cookies: {}, vars: {} };
  }
}
function saveSession(file, s) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + '.' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(s, null, 2));
    fs.renameSync(tmp, file);
  } catch (e) {
    console.error(JSON.stringify({ error: 'cannot write session file: ' + e.message }));
  }
}
function cookieHeader(host, s) {
  const raw = (s.cookies || {})[host] || [];
  const names = new Set();
  const parts = [];
  for (const c of raw) {
    const nv = c.split(';')[0].trim();
    if (!nv || !nv.includes('=')) continue;
    const name = nv.split('=')[0].trim();
    if (names.has(name)) continue;
    names.add(name);
    parts.push(nv);
  }
  return parts.join('; ');
}
function absorbSetCookies(s, host, setCookies) {
  if (!setCookies || !setCookies.length) return;
  s.cookies = s.cookies || {};
  const jar = s.cookies[host] || (s.cookies[host] = []);
  for (const raw of setCookies) {
    const name = (raw.split(';')[0] || '').split('=')[0].trim();
    const i = jar.findIndex((c) => (c.split(';')[0] || '').split('=')[0].trim() === name);
    if (i >= 0) jar[i] = raw;
    else jar.push(raw);
  }
}

// Substitute {{name}} placeholders with session vars + --var values.
function applyVars(text, vars) {
  if (text == null) return text;
  return String(text).replace(/\{\{([A-Za-z0-9_.-]+)\}\}/g, (m, name) =>
    vars[name] != null ? String(vars[name]) : m
  );
}

// Vary one request for a given value. FUZZ (in the url and/or the body) is substituted
// wherever it appears — /Order/FUZZ for path IDOR, {"id":"FUZZ"} for body IDOR/SSRF.
// If there is no FUZZ anywhere, the value is set as a query param (the original behaviour).
function varyRequest(url, data, param, value) {
  const inUrl = url.includes('FUZZ');
  const inData = data != null && data.includes('FUZZ');
  if (inUrl || inData) {
    return {
      url: inUrl ? url.split('FUZZ').join(value) : url,
      data: inData ? data.split('FUZZ').join(value) : data,
    };
  }
  const u = new URL(url);
  u.searchParams.set(param, value);
  return { url: u.toString(), data };
}

// Multipart body from --form fields and --upload file fields.
function buildMultipart(fields, uploads) {
  const boundary = '----Stavros' + Math.random().toString(16).slice(2);
  const parts = [];
  for (const [k, v] of Object.entries(fields || {}))
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`);
  for (const [field, filepath] of uploads || []) {
    const fname = path.basename(filepath);
    let content;
    try {
      content = fs.readFileSync(filepath);
    } catch (e) {
      console.error(JSON.stringify({ error: 'cannot read upload file: ' + e.message }));
      process.exit(2);
    }
    parts.push(
      `--${boundary}\r\nContent-Disposition: form-data; name="${field}"; filename="${fname}"\r\n` +
        'Content-Type: application/octet-stream\r\n\r\n'
    );
    parts.push(content);
    parts.push('\r\n');
  }
  parts.push(`--${boundary}--\r\n`);
  const body = Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p, 'utf8'))));
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}

// Decompress gzip/deflate/br bodies (some servers ignore Accept-Encoding: identity).
function decodeBody(buf, encoding) {
  if (!buf || !buf.length) return buf;
  try {
    if (encoding === 'gzip') return zlib.gunzipSync(buf);
    if (encoding === 'deflate') return zlib.inflateSync(buf);
    if (encoding === 'br') return zlib.brotliDecompressSync(buf);
  } catch {}
  return buf;
}

// Token-overlap similarity in [0,1]: 1 = identical, 0 = nothing in common.
function similarity(a, b) {
  const ta = String(a || '').split(/\s+/).filter(Boolean);
  const tb = String(b || '').split(/\s+/).filter(Boolean);
  if (!ta.length && !tb.length) return 1;
  if (!ta.length || !tb.length) return 0;
  const setB = new Set(tb);
  let hit = 0;
  for (const w of ta) if (setB.has(w)) hit++;
  return hit / Math.max(ta.length, tb.length);
}

// Response headers that matter for security findings (missing CSP/HSTS/XFO, cookie flags, F7/F8).
const SEC_HEADERS = ['content-type', 'set-cookie', 'strict-transport-security', 'content-security-policy',
  'x-frame-options', 'x-content-type-options', 'referrer-policy', 'server'];
function pickSecHeaders(h) {
  const out = {};
  for (const k of SEC_HEADERS) if (h[k] != null) out[k] = h[k];
  return out;
}

// Flatten an object into {dotted.path: finite number} for --race-watch state diffing.
function flattenNumbers(obj, prefix, depth, out) {
  out = out || {};
  if (obj == null || typeof obj !== 'object') return out;
  depth = depth || 0;
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? prefix + '.' + k : k;
    if (typeof v === 'number' && Number.isFinite(v)) out[key] = v;
    else if (v && typeof v === 'object' && depth < 3) flattenNumbers(v, key, depth + 1, out);
  }
  return out;
}

function parseArgs(argv) {
  const a = {
    headers: [], vary: null, method: 'GET', data: null, url: null, as: null, showBody: false,
    timeout: DEFAULT_TIMEOUT, follow: false, session: null, extracts: [], vars: {}, diff: false,
    race: 0, forms: {}, uploads: [], noPace: false, raceWatch: null, watchFields: null,
    allowMetadata: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--url') a.url = argv[++i];
    else if (k === '--method') a.method = argv[++i].toUpperCase();
    else if (k === '--header') a.headers.push(argv[++i]);
    else if (k === '--data') a.data = argv[++i];
    else if (k === '--vary') a.vary = argv[++i]; // 'param=v1,v2,v3'
    else if (k === '--as') a.as = argv[++i]; // identity name from auth.json
    else if (k === '--show-body') a.showBody = true; // include first 2KB of response body as evidence
    else if (k === '--timeout') a.timeout = parseInt(argv[++i], 10) || DEFAULT_TIMEOUT;
    else if (k === '--follow') a.follow = true;
    else if (k === '--session' || k === '--cookies') a.session = argv[++i];
    else if (k === '--extract') a.extracts.push(argv[++i]); // 'name=regex'
    else if (k === '--var') { const kv = argv[++i]; const eq = kv.indexOf('='); a.vars[kv.slice(0, eq)] = kv.slice(eq + 1); }
    else if (k === '--diff') a.diff = true;
    else if (k === '--race') a.race = parseInt(argv[++i], 10) || 0;
    else if (k === '--race-watch') a.raceWatch = argv[++i]; // state URL snapshotted before/after the volley
    else if (k === '--watch-field') a.watchFields = argv[++i]; // restrict delta report to these JSON numeric fields
    else if (k === '--upload') { const kv = argv[++i]; const eq = kv.indexOf('='); a.uploads.push([kv.slice(0, eq), kv.slice(eq + 1)]); }
    else if (k === '--form') { const kv = argv[++i]; const eq = kv.indexOf('='); a.forms[kv.slice(0, eq)] = kv.slice(eq + 1); }
    else if (k === '--no-pace') a.noPace = true;
    else if (k === '--allow-metadata-target') a.allowMetadata = true; // B9 explicit opt-in
  }
  return a;
}

// B9 second-layer verdict helper. `scopeAuthorized` = the scope-guard layer already
// passed for THIS target (inScope and/or DNS pin) — it unlocks only the PRIVATE tier
// (RFC1918/ULA, internal-lab targets); the HARD tier (loopback/link-local/metadata)
// stays denied without the explicit opt-in. Denials are fatal; passes are logged once
// per target into the existing stderr flow.
function ssrfVerdictOrExit(target, opts, label) {
  const v = ssrfGuard.checkTarget(target, opts);
  if (!v.ok) {
    console.error(JSON.stringify({ blocked: String(target), gate: 'ssrf-guard', tier: v.tier, range: v.range, reason: 'B9 ' + v.why }));
    process.exit(1);
  }
  console.error(`[ssrf] ${label}: pass (${v.tier}${v.range ? ' · ' + v.range : ''})`);
  return v;
}

function guard(target, scope, opts) {
  const r = inScope(target, scope);
  if (!r.ok) {
    console.error(JSON.stringify({ blocked: target, reason: r.reason }));
    process.exit(1);
  }
  // B9 second layer (hostname level: literal-IP hosts + metadata hostnames). The first
  // layer JUST passed for this exact target -> private tier unlocked; hard tier still
  // requires --allow-metadata-target. The pinned ADDRESS is re-judged per hop in sendChain.
  ssrfVerdictOrExit(target, { allowMetadata: !!(opts && opts.allowMetadata), scopeAuthorized: true }, 'guard ' + target);
}

// One HTTP request. With `proxy` (the local egress proxy in chained mode) the request rides the
// anonymized chain: http via absolute-form to the proxy, https via CONNECT+TLS tunnel — DNS is
// resolved at the SOCKS upstream, never locally (no leak). Without it, direct + DNS-pinned.
function oneRequest(u, method, headers, body, timeoutMs, pin, proxy) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    const handler = (res) => {
      const chunks = [];
      let len = 0;
      res.on('data', (d) => { len += d.length; chunks.push(d); });
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        const bodyBuf = decodeBody(raw, res.headers['content-encoding']);
        finish({
          status: res.statusCode,
          bytes: len,
          bodyBuf,
          headers: res.headers,
          ms: Date.now() - t0,
        });
      });
    };
    const arm = (req) => {
      req.on('timeout', () => { req.destroy(); finish({ timeout: true, ms: Date.now() - t0 }); });
      req.on('error', (e) => finish({ error: e.message, ms: Date.now() - t0 }));
      if (body) req.write(body);
      req.end();
    };
    if (proxy) {
      if (u.protocol === 'https:') {
        // Tunnel (CONNECT + TLS) first; then http.request writes over the secure socket.
        tlsTunnel(proxy, u.hostname, +u.port || 443).then((sock) => {
          arm(http.request({
            host: u.hostname, port: +u.port || 443, method, path: u.pathname + u.search,
            headers, timeout: timeoutMs, agent: false, createConnection: () => sock,
          }, handler));
        }).catch((e) => finish({ error: e.message, ms: Date.now() - t0 }));
        return;
      }
      // Plain http: absolute-form to the local egress proxy (Host must stay the target's).
      const hdrs = Object.assign({}, headers, { Host: u.host });
      arm(http.request({
        host: '127.0.0.1', port: proxy.port, method, path: u.href, headers: hdrs,
        timeout: timeoutMs, agent: false,
      }, handler));
      return;
    }
    const lib = u.protocol === 'https:' ? https : http;
    const opts = { method, headers, timeout: timeoutMs };
    // Node >= 20 (autoSelectFamily / Happy Eyeballs) invokes the custom `lookup` through
    // lookupAndConnectMultiple, which expects the callback to receive an ARRAY of
    // {address, family} records (a bare string is iterated char-by-char and throws
    // "Invalid IP address: undefined").
    if (pin) opts.lookup = (hostname, o, cb) => cb(null, [{ address: pin.address, family: pin.family }]);
    arm(lib.request(u, opts, handler));
  });
}

// Build the human-readable result from a raw response.
function finishResult(r, opts) {
  if (r.timeout) return { timeout: true, ms: r.ms };
  if (r.error) return { error: r.error, ms: r.ms };
  const waf = r.status === 403 || r.status === 429 ||
    /cloudflare|akamai|imperva|awselb|mod_security/i.test((r.headers.server || '') + (r.headers['x-cdn'] || ''));
  const out = {
    status: r.status,
    bytes: r.bytes,
    ms: r.ms,
    location: r.headers.location || null,
    retry_after: r.headers['retry-after'] || null,
    waf: waf || undefined,
    headers: pickSecHeaders(r.headers),
  };
  const needBody = opts.showBody || opts.diff;
  if (needBody) {
    const text = r.bodyBuf ? r.bodyBuf.toString('utf8') : '';
    out.body = text.slice(0, BODY_CAP);
    out.body_truncated = text.length > BODY_CAP ? true : undefined;
    if (opts.keepFull) out._full = text; // internal: full body for similarity (vary mode only)
  }
  return out;
}

// headersFn(hostname) is called per hop so cookies absorbed on a redirect hop are
// included on the next hop. body/method are fixed for the initial request.
async function sendChain(target, method, headersFn, body, opts, scope, proxy) {
  let u = new URL(target);
  let curBody = body;
  let curMethod = method;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    let pin = null;
    if (proxy) {
      // Chained: scope-check the hostname but resolve DNS remotely (at the SOCKS upstream).
      const g = inScope(u.toString(), scope);
      if (!g.ok) return { blocked: true, reason: g.reason, target: u.toString() };
      // B9: no local pin exists in chained mode — judge the hostname itself.
      const v = ssrfGuard.checkTarget(u.toString(), { allowMetadata: !!opts.allowMetadata, scopeAuthorized: true });
      if (!v.ok) return { blocked: true, reason: 'B9 ' + v.why, ssrf: { tier: v.tier, range: v.range }, target: u.toString() };
      if (i === 0) console.error(`[ssrf] hop0 ${u.hostname}: pass (${v.tier}${v.range ? ' · ' + v.range : ''})`);
    } else {
      pin = await resolveAndGuard(u.toString(), scope);
      if (pin.blocked) return { blocked: true, reason: pin.reason, target: u.toString() };
      // B9: re-judge the PINNED ADDRESS on EVERY hop (redirects are re-pinned here).
      const v = ssrfGuard.checkAddress(pin.address, { allowMetadata: !!opts.allowMetadata, scopeAuthorized: true });
      if (!v.ok) return { blocked: true, reason: 'B9 ' + v.why, ssrf: { tier: v.tier, range: v.range }, target: u.toString() };
      if (i === 0) console.error(`[ssrf] hop0 pinned ${pin.address}: pass (${v.tier}${v.range ? ' · ' + v.range : ''})`);
    }
    const r = await oneRequest(u, curMethod, headersFn(u.hostname), curBody, opts.timeout, pin, proxy);
    const res = finishResult(r, opts);
    res.target = u.toString();
    res.hop = i;
    if (opts.session && r.headers && r.headers['set-cookie']) {
      absorbSetCookies(opts.sessionState, u.hostname, r.headers['set-cookie']);
      saveSession(opts.session, opts.sessionState);
    }
    if (opts.follow && r.status >= 300 && r.status < 400 && r.headers.location && !r.timeout && !r.error) {
      let next;
      try {
        next = new URL(r.headers.location, u).toString();
      } catch {
        return res;
      }
      const g = inScope(next, scope);
      if (!g.ok) {
        res.blocked_redirect = g.reason;
        return res;
      }
      u = new URL(next);
      curBody = null; // follow redirects as GET by convention
      curMethod = 'GET';
      continue;
    }
    return res;
  }
  return { error: 'too many redirects', target: u.toString() };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  // B9: env opt-in equivalent to --allow-metadata-target (loud, never silent).
  if (!args.allowMetadata && ssrfGuard.envOptIn()) {
    args.allowMetadata = true;
    console.error('[ssrf] ALLOW_METADATA_TARGET attivo: metadata/loopback esplicitamente consentiti (opt-in operatore)');
  }
  if (!args.url) {
    console.error(
      'usage: node repeater.js --url <u> [--method M] [--header "K: V"]... [--data D] [--vary "param=v1,v2"] [--show-body]\n' +
        '  --vary sets a query param, OR substitutes the literal FUZZ in the URL or --data body\n' +
        '    (path IDOR: --url .../Order/FUZZ --vary "id=1,2,3"; body IDOR/SSRF: --data \'{"id":"FUZZ"}\' --vary "id=1,2")\n' +
        '  --show-body includes the first 2KB of each response as PoC evidence\n' +
        '  --follow --timeout <ms> --session <file> --cookies <file> --extract "name=regex" --var k=v\n' +
        '  --diff (body similarity vs baseline) --race <n> [--race-watch <url>] [--watch-field f1,f2]\n' +
        '  --upload field=path --form k=v --no-pace\n' +
        '  --allow-metadata-target lift the B9 metadata/loopback default-deny (explicit opt-in)'
    );
    process.exit(2);
  }
  if (args.session == null && args.extracts.length) {
    console.error(JSON.stringify({ error: '--extract requires --session <file>' }));
    process.exit(2);
  }
  if (args.race && args.vary) {
    console.error(JSON.stringify({ error: '--race and --vary are mutually exclusive' }));
    process.exit(2);
  }

  // identity headers first; explicit --header can override.
  args.headers = [...(await resolveIdentity(args.as)), ...args.headers];

  // session state
  let session = { cookies: {}, vars: {} };
  if (args.session) {
    session = loadSession(args.session);
    args.sessionState = session;
  }
  const allVars = Object.assign({}, session.vars || {}, args.vars);
  const hasUA = args.headers.some((h) => h.toLowerCase().startsWith('user-agent:'));
  if (!hasUA) args.headers.unshift('User-Agent: ' + DEFAULT_UA);
  const hasAcceptEnc = args.headers.some((h) => h.toLowerCase().startsWith('accept-encoding:'));
  if (!hasAcceptEnc) args.headers.push('Accept-Encoding: identity');

  args.url = privacy.rehydrate(args.url);
  args.data = privacy.rehydrate(args.data);
  args.headers = args.headers.map(privacy.rehydrate);

  // body: multipart takes precedence over --data
  let data = args.data;
  if (args.uploads.length || Object.keys(args.forms).length) {
    const mp = buildMultipart(args.forms, args.uploads);
    data = mp.body;
    args.headers.push('Content-Type: ' + mp.contentType);
  }
  const bodyIsBuffer = Buffer.isBuffer(data);

  const scope = loadScope();
  privacy.seedFromScope(scope);
  // Chained egress: if the egress proxy is running WITH a SOCKS5 anonymizer, every request from
  // this shell rides the chain too (exit IP masked). Direct proxy (no socks5) is NOT used — it
  // would not hide anything, just add a hop.
  const egress = loadEgressProxy();
  const proxy = egress && egress.socks5 ? { port: egress.port, socks5: egress.socks5 } : null;
  if (proxy) {
    console.error('[egress] chained via egress-proxy:' + egress.port + ' -> socks5 ' + egress.socks5.host + ':' + egress.socks5.port + ' (exit IP masked)');
  }
  const rps = Math.max(0.1, scope.max_requests_per_second || 2);
  const pace = (minGap) => { if (!args.noPace) wait(rps, minGap != null ? { minGap } : {}); };

  const headerMap = {};
  for (const h of args.headers) {
    const i = h.indexOf(':');
    if (i > 0) headerMap[h.slice(0, i).trim()] = h.slice(i + 1).trim();
  }
  const headersFor = (hostname) => {
    const out = {};
    for (const [k, v] of Object.entries(headerMap)) out[k] = applyVars(v, allVars);
    if (args.session) {
      const cookie = cookieHeader(hostname, session);
      if (cookie && !out.Cookie) out.Cookie = cookie;
    }
    return out;
  };

  const results = [];
  args.keepFull = !!(args.diff && args.vary); // full body needed only for vary diffing

  // ---- --race N: concurrent identical volley (TOCTOU / double-redemption) ----
  if (args.race) {
    const urlStr = applyVars(args.url, allVars);
    guard(urlStr, scope, args);
    let pin = null;
    if (!proxy) {
      pin = await resolveAndGuard(urlStr, scope);
      if (pin.blocked) {
        console.error(JSON.stringify({ blocked: urlStr, reason: pin.reason }));
        process.exit(1);
      }
      // B9: judge the pinned address before the volley (same second layer as sendChain).
      const v = ssrfGuard.checkAddress(pin.address, { allowMetadata: !!args.allowMetadata, scopeAuthorized: true });
      if (!v.ok) {
        console.error(JSON.stringify({ blocked: urlStr, gate: 'ssrf-guard', tier: v.tier, range: v.range, reason: 'B9 ' + v.why }));
        process.exit(1);
      }
      console.error(`[ssrf] race pinned ${pin.address}: pass (${v.tier}${v.range ? ' · ' + v.range : ''})`);
    }
    // --race-watch <url>: snapshot a state endpoint before/after the volley and diff its JSON
    // numbers. A race is only provable through OBSERVED MUTATION (balance drops twice, count
    // increments N+1) — response statuses alone proved nothing on bench seed 3412.
    let snap = null;
    if (args.raceWatch) {
      const watchUrl = applyVars(args.raceWatch, allVars);
      guard(watchUrl, scope, args);
      const readState = async () => {
        pace();
        const r = await oneRequest(new URL(watchUrl), 'GET', headersFor(new URL(watchUrl).hostname), null, args.timeout, pin, proxy);
        let numbers = {};
        try { numbers = flattenNumbers(JSON.parse((r.bodyBuf || Buffer.alloc(0)).toString('utf8'))); } catch (e) {}
        return { status: r.status, bytes: r.bytes, numbers };
      };
      snap = readState;
    }
    const body = bodyIsBuffer ? data : applyVars(data, allVars);
    pace();
    const before = snap ? await snap() : null;
    const volley = await Promise.all(
      Array.from({ length: args.race }, (_, index) =>
        oneRequest(new URL(urlStr), args.method, headersFor(new URL(urlStr).hostname), body, args.timeout, pin, proxy).then((r) => ({
          index,
          ...finishResult(r, args),
        }))
      )
    );
    let watch = null;
    if (snap) {
      const after = await snap();
      const deltas = {};
      const filter = args.watchFields ? String(args.watchFields).split(',').map((s) => s.trim()) : null;
      for (const k of Object.keys(after.numbers)) {
        if (filter && !filter.some((f) => k === f || k.startsWith(f + '.'))) continue;
        if (before.numbers[k] !== undefined && after.numbers[k] !== before.numbers[k]) deltas[k] = after.numbers[k] - before.numbers[k];
      }
      watch = { url: applyVars(args.raceWatch, allVars), before, after, deltas,
        mutated: Object.keys(deltas).length > 0 || before.status !== after.status || before.bytes !== after.bytes };
    }
    results.push({ label: 'race-' + args.race + (watch ? '-watch' : ''), url: urlStr, ...(watch ? { watch } : {}), volley });
    if (args.session) saveSession(args.session, session);
    return console.log(privacy.tokenize(JSON.stringify(results, null, 2)));
  }

  // ---- single request ----
  if (!args.vary) {
    const urlStr = applyVars(args.url, allVars);
    guard(urlStr, scope, args);
    const body = bodyIsBuffer ? data : applyVars(data, allVars);
    pace();
    const res = await sendChain(urlStr, args.method, headersFor, body, args, scope, proxy);
    if (args.extracts.length && !res.error && !res.timeout) {
      const text = res.body != null ? res.body : '';
      for (const spec of args.extracts) {
        const eq = spec.indexOf('=');
        const name = spec.slice(0, eq);
        const re = new RegExp(spec.slice(eq + 1));
        const m = (text + '\n' + (res.location || '')).match(re);
        if (m) {
          session.vars = session.vars || {};
          session.vars[name] = m[1] || m[0];
          res.extracted = Object.assign({}, res.extracted, { [name]: session.vars[name] });
        }
      }
      if (args.session) saveSession(args.session, session);
    }
    results.push({ label: 'single', ...res });
    return console.log(privacy.tokenize(JSON.stringify(results, null, 2)));
  }

  // ---- --vary: iterate values ----
  const eq = args.vary.indexOf('=');
  const param = args.vary.slice(0, eq);
  const values = args.vary.slice(eq + 1).split(',');
  let baseline = null;
  for (const v of values) {
    const { url: target, data: d } = varyRequest(args.url, args.data, param, v);
    const urlStr = applyVars(target, allVars);
    guard(urlStr, scope, args);
    const body = bodyIsBuffer ? d : applyVars(d, allVars);
    pace();
    const r = await sendChain(urlStr, args.method, headersFor, body, args, scope, proxy);
    const isBaseline = !baseline && !r.error && !r.timeout;
    if (isBaseline) baseline = r;
    const entry = { [param]: v, ...r };
    // diff only against a PREVIOUS (non-self) baseline
    if (args.diff && !isBaseline && !r.error && !r.timeout && r._full != null && baseline._full != null) {
      entry.body_similarity = +similarity(baseline._full, r._full).toFixed(3);
    }
    delete entry._full; // never leak the full body into output
    if (!isBaseline && !r.error && !r.timeout) {
      entry.diff_bytes = r.bytes != null && baseline.bytes != null ? r.bytes - baseline.bytes : null;
      entry.diff_status = baseline.status != null ? r.status !== baseline.status : null;
    }
    if (args.extracts.length && !r.error && !r.timeout) {
      const text = r.body != null ? r.body : '';
      for (const spec of args.extracts) {
        const speq = spec.indexOf('=');
        const name = spec.slice(0, speq);
        const re = new RegExp(spec.slice(speq + 1));
        const m = (text + '\n' + (r.location || '')).match(re);
        if (m) {
          session.vars = session.vars || {};
          session.vars[name] = m[1] || m[0];
          entry.extracted = Object.assign({}, entry.extracted, { [name]: session.vars[name] });
        }
      }
    }
    results.push(entry);
    // Back off on rate-limit: honor Retry-After, else triple the gap.
    const extra = r.status === 429 ? Math.max((parseInt(r.retry_after, 10) || 0) * 1000, (1000 / rps) * 3) : 0;
    if (extra) await new Promise((s) => setTimeout(s, extra));
  }
  if (args.session) saveSession(args.session, session);
  console.log(privacy.tokenize(JSON.stringify(results, null, 2)));
}

module.exports = { varyRequest, pickSecHeaders, applyVars, buildMultipart, similarity, decodeBody, cookieHeader, absorbSetCookies, sendChain, resolveIdentity, DEFAULT_UA };
if (require.main === module) main();
