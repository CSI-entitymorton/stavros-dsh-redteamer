#!/usr/bin/env node
// Client-side / DOM-XSS surface checker via Chrome DevTools Protocol (zero-dep, Node >= 22).
// Requires a browser with remote debugging enabled, e.g.:
//   Kali/Linux:  chromium --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-stavros
//   Windows:     chrome.exe --remote-debugging-port=9222 --user-data-dir=%TEMP%\chrome-stavros
//   OR Obscura:  node tools/obscura.js serve --port 9222 --stealth   (Rust engine, CDP-compatible)
// Usage:
//   node tools/dom-check.js <url> [--cdp-port 9222] [--eval 'js'] [--timeout 8000]
//                             [--backend chrome|obscura]
// --backend obscura auto-starts an ephemeral `obscura serve` on the CDP port if none is
// listening (pinned to the egress gateway when it is running), uses it for ONE check, then
// shuts it down. The engine is NOT Chromium: treat results as surface discovery and CONFIRM
// DOM-XSS PoCs on real Chrome.
// Loads the page with instrumentation injected BEFORE any page script runs, then reports:
//   - title, script srcs, inline-script sink grep (innerHTML/eval/document.write/postMessage/...)
//   - localStorage/sessionStorage keys, document.cookie names
//   - postMessage listeners (handler source) and outgoing postMessage target origins
//   - forms (action/method) and javascript: links
// --eval runs arbitrary JS after load (returnByValue) — use it to CONFIRM a DOM-XSS PoC
// (e.g. check whether a payload reached a sink / an alert fired).
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const { loadScope, inScope } = require('./scope-guard');
const { wait } = require('./pace');
const obscura = require('./obscura');

// Platform-aware Chrome/Chromium launch hint for the CDP requirement (Kali ships chromium).
function browserLaunchHint(port) {
  const udd = process.platform === 'win32' ? '%TEMP%\\chrome-stavros' : '/tmp/chrome-stavros';
  if (process.platform === 'win32') return `chrome.exe --remote-debugging-port=${port} --user-data-dir=${udd}`;
  if (process.platform === 'darwin')
    return `"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --remote-debugging-port=${port} --user-data-dir=${udd}`;
  // Linux: prefer chromium (Kali default), fall back to google-chrome / chromium-browser.
  for (const bin of ['chromium', 'google-chrome', 'chromium-browser']) {
    if (spawnSync('which', [bin], { stdio: 'ignore' }).status === 0)
      return `${bin} --remote-debugging-port=${port} --user-data-dir=${udd}`;
  }
  return `chromium --remote-debugging-port=${port} --user-data-dir=${udd}`;
}

function httpJson(method, url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, timeout: timeoutMs }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(d));
        } catch (e) {
          reject(new Error('bad JSON from ' + url + ' (HTTP ' + res.statusCode + ')'));
        }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout talking to CDP at ' + url)); });
    req.on('error', reject);
    req.end();
  });
}

function httpGetJson(url, timeoutMs) {
  return httpJson('GET', url, timeoutMs);
}

// Fetch /json/list and make sure a page target exists. Chrome (with a tab open) already has
// one; `obscura serve` starts with NO page, so ask the endpoint to create one (about:blank).
// Chrome >= 111 requires PUT /json/new?<url>; older builds/obscura answer plain GET — try both.
async function ensurePageTarget(port, timeoutMs) {
  const base = 'http://127.0.0.1:' + port;
  const targets = await httpGetJson(base + '/json/list', timeoutMs);
  if (!Array.isArray(targets)) throw new Error('unexpected /json/list response');
  const existing = targets.find((t) => t.type === 'page');
  if (existing) return { targets, page: existing };
  for (const method of ['PUT', 'GET']) {
    try {
      const t = await httpJson(method, base + '/json/new?about:blank', timeoutMs);
      if (t && t.webSocketDebuggerUrl && t.type === 'page') return { targets: [t], page: t };
      if (t && t.webSocketDebuggerUrl) return { targets: [t], page: t };
    } catch (e) { /* try next method */ }
  }
  return { targets, page: null };
}

// Poll until a CDP endpoint answers on the port (used after auto-starting obscura serve).
async function waitForCdp(port, deadlineMs) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    const v = await httpGetJson('http://127.0.0.1:' + port + '/json/version', 1500).catch(() => null);
    if (v) return v;
    await new Promise((s) => setTimeout(s, 250));
  }
  return null;
}

function cdpConnect(wsUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const pending = new Map();
    let id = 0;
    const timer = setTimeout(() => reject(new Error('CDP connect timeout')), timeoutMs);
    ws.onopen = () => {
      clearTimeout(timer);
      resolve({
        ws,
        send(method, params) {
          return new Promise((res, rej) => {
            const mid = ++id;
            pending.set(mid, { res, rej });
            ws.send(JSON.stringify({ id: mid, method, params: params || {} }));
          });
        },
        close() { try { ws.close(); } catch {} },
      });
    };
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.id && pending.has(m.id)) {
        const p = pending.get(m.id);
        pending.delete(m.id);
        if (m.error) p.rej(new Error(JSON.stringify(m.error)));
        else p.res(m.result);
      }
    };
    ws.onerror = () => reject(new Error('CDP websocket error'));
  });
}

const INSTRUMENT = `
(() => {
  try {
    window.__msgHandlers = [];
    const origAdd = window.addEventListener.bind(window);
    window.addEventListener = function (type, fn, ...rest) {
      if (type === 'message') { try { window.__msgHandlers.push(String(fn).slice(0, 300)); } catch (e) {} }
      return origAdd(type, fn, ...rest);
    };
    window.__posted = [];
    const origPost = window.postMessage.bind(window);
    window.postMessage = function (msg, origin, ...rest) {
      try { window.__posted.push(String(origin)); } catch (e) {}
      return origPost(msg, origin, ...rest);
    };
  } catch (e) {}
})();
`;

const SINK_RE = /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function|setTimeout\s*\(\s*[\x22\x27\x60]|srcdoc\s*=|location\s*=|window\.location|\.src\s*=|postMessage\s*\()/g;

function collectExpr() {
  return `(() => {
    const out = { title: document.title, url: location.href, readyState: document.readyState };
    try {
      out.scripts = [...document.scripts].map(s => s.src || '(inline)').slice(0, 50);
      out.inline_script_count = [...document.scripts].filter(s => !s.src).length;
      let snippets = [];
      for (const s of document.scripts) {
        if (s.src) continue;
        const t = s.textContent || '';
        let m;
        const re = /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function|setTimeout\s*\(\s*[\x22\x27\x60]|srcdoc\s*=|location\s*=|window\.location|\.src\s*=|postMessage\s*\()/g;
        while ((m = re.exec(t)) && snippets.length < 10) snippets.push(m[1] + ' ... ' + t.slice(Math.max(0, m.index - 60), m.index + 120));
      }
      out.sink_snippets = snippets;
    } catch (e) { out.scripts_error = String(e); }
    try {
      out.localStorage_keys = Object.keys(localStorage).slice(0, 50).map(k => k + '=' + String(localStorage.getItem(k)).slice(0, 60));
      out.sessionStorage_keys = Object.keys(sessionStorage).slice(0, 30);
    } catch (e) {}
    try { out.cookie_names = document.cookie.split(';').map(c => c.trim().split('=')[0]).filter(Boolean); } catch (e) {}
    try { out.postmessage_handlers = (window.__msgHandlers || []).slice(0, 20); } catch (e) {}
    try { out.posted_origins = (window.__posted || []).slice(0, 20); } catch (e) {}
    try {
      out.forms = [...document.forms].map(f => ({ action: f.action, method: f.method, fields: [...f.elements].map(el => el.name).filter(Boolean).slice(0, 10) })).slice(0, 30);
    } catch (e) {}
    try {
      out.javascript_links = [...document.querySelectorAll('a[href^="javascript:"]')].map(a => a.getAttribute('href').slice(0, 200)).slice(0, 20);
    } catch (e) {}
    return out;
  })()`;
}

async function main() {
  const argv = process.argv.slice(2);
  const url = argv[0];
  const flag = (name) => { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] ? argv[i + 1] : null; };
  const port = +flag('cdp-port') || 9222;
  const timeout = +flag('timeout') || 10000;
  const evalJs = flag('eval');
  const backend = flag('backend') || 'chrome';
  if (!url) {
    console.error('usage: node tools/dom-check.js <url> [--cdp-port 9222] [--eval "js"] [--backend chrome|obscura]');
    process.exit(2);
  }
  if (typeof WebSocket === 'undefined') {
    console.error(JSON.stringify({ error: 'global WebSocket unavailable — requires Node >= 22' }));
    process.exit(1);
  }
  const scope = loadScope();
  const g = inScope(url, scope);
  if (!g.ok) {
    console.error(JSON.stringify({ blocked: url, reason: g.reason }));
    process.exit(1);
  }
  wait(Math.max(0.1, scope.max_requests_per_second || 2));

  // Optional Obscura backend: auto-start an ephemeral CDP server if nothing listens.
  let obscuraChild = null;
  if (backend === 'obscura') {
    const bin = obscura.resolveBin();
    if (!bin) {
      console.error(JSON.stringify({ error: 'obscura binary not found (--backend obscura)', hint: 'run ./install-tools.sh or set STAVROS_OBSCURA_BIN' }));
      process.exit(1);
    }
    let version = null;
    try { version = await httpGetJson('http://127.0.0.1:' + port + '/json/version', 1200); } catch {}
    if (!version) {
      const args = obscura.buildArgs('serve', [], { port });
      obscuraChild = spawn(bin.bin, args, { stdio: 'ignore' });
      version = await waitForCdp(port, 15000);
      if (!version) {
        try { obscuraChild.kill(); } catch {}
        console.error(JSON.stringify({ error: 'obscura serve did not come up on port ' + port, hint: 'node tools/obscura.js serve --port ' + port + ' --stealth (run it manually to see the error)' }));
        process.exit(1);
      }
    }
  } else if (backend !== 'chrome') {
    console.error(JSON.stringify({ error: 'unknown --backend: ' + backend, hint: 'chrome | obscura' }));
    process.exit(2);
  }

  let targets, page;
  try {
    ({ targets, page } = await ensurePageTarget(port, 3000));
  } catch (e) {
    console.error(JSON.stringify({
      error: 'cannot reach Chrome DevTools on port ' + port + ': ' + e.message,
      hint: backend === 'obscura'
        ? 'node tools/obscura.js serve --port ' + port + ' --stealth'
        : browserLaunchHint(port) + '   |   node tools/obscura.js serve --port ' + port,
    }));
    if (obscuraChild) { try { obscuraChild.kill(); } catch {} }
    process.exit(1);
  }
  if (!page) {
    console.error(JSON.stringify({ error: 'no page target found and /json/new failed', targets: targets.map((t) => t.type + ':' + t.url).slice(0, 10) }));
    if (obscuraChild) { try { obscuraChild.kill(); } catch {} }
    process.exit(1);
  }

  let cdp;
  try {
    cdp = await cdpConnect(page.webSocketDebuggerUrl, 5000);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: INSTRUMENT });
    await cdp.send('Page.navigate', { url });
    // wait for load (poll readyState; generous timeout)
    const deadline = Date.now() + timeout;
    for (;;) {
      const r = await cdp.send('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
      if (r.result && r.result.value === 'complete') break;
      if (Date.now() > deadline) break;
      await new Promise((s) => setTimeout(s, 250));
    }
    let result;
    if (evalJs) {
      const r = await cdp.send('Runtime.evaluate', { expression: evalJs, returnByValue: true, awaitPromise: true });
      result = r.result && r.result.value !== undefined
        ? { eval_result: r.result.value }
        : { eval_exception: r.exceptionDetails ? r.exceptionDetails.text : null };
    } else {
      const r = await cdp.send('Runtime.evaluate', { expression: collectExpr(), returnByValue: true });
      result = r.result && r.result.value !== undefined ? r.result.value : { eval_error: r.exceptionDetails ? r.exceptionDetails.text : 'no value' };
    }
    console.log(JSON.stringify({ target: url, cdp_port: port, backend, ...result }, null, 2));
  } finally {
    if (cdp) cdp.close();
    if (obscuraChild) { try { obscuraChild.kill(); } catch {} }
  }
}

module.exports = { collectExpr, INSTRUMENT, SINK_RE, ensurePageTarget, waitForCdp };
if (require.main === module) main();
