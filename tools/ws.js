#!/usr/bin/env node
// WebSocket tester (zero-dep — uses Node's native WebSocket client, Node >= 22).
//   node tools/ws.js --url ws://host/path [--message 'text'] [--json '{"a":1}']
//                    [--header "K: V"]... [--count N] [--timeout 8000]
// Sends the message (or just connects), collects up to N responses, reports frames.
// Scope-guarded on the ws host like everything else.
const { loadScope, inScope } = require('./scope-guard');
const { wait } = require('./pace');

async function main() {
  const argv = process.argv.slice(2);
  const flag = (name) => { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] ? argv[i + 1] : null; };
  const url = flag('url');
  if (!url) {
    console.error('usage: node tools/ws.js --url ws://host/path [--message M] [--json D] [--header "K: V"] [--count N]');
    process.exit(2);
  }
  const scope = loadScope();
  const g = inScope(url, scope);
  if (!g.ok) {
    console.error(JSON.stringify({ blocked: url, reason: g.reason }));
    process.exit(1);
  }
  if (typeof WebSocket === 'undefined') {
    console.error(JSON.stringify({ error: 'global WebSocket unavailable — requires Node >= 22' }));
    process.exit(1);
  }
  const count = +flag('count') || 3;
  const timeoutMs = +flag('timeout') || 8000;
  const headers = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--header' && argv[i + 1]) {
      const h = argv[i + 1];
      const j = h.indexOf(':');
      if (j > 0) headers[h.slice(0, j).trim()] = h.slice(j + 1).trim();
    }
  }
  const msg = flag('json') ? flag('json') : flag('message');
  const msgType = flag('json') ? 'json' : flag('message') ? 'text' : null;

  wait(Math.max(0.1, scope.max_requests_per_second || 2));
  const ws = new WebSocket(url, { headers });
  const out = { url, connected: false, frames: [], errors: [] };

  await new Promise((resolve) => {
    const timer = setTimeout(() => { ws.close(); resolve(); }, timeoutMs);
    ws.onopen = () => {
      out.connected = true;
      if (msg != null) ws.send(msg);
    };
    ws.onmessage = (e) => {
      if (out.frames.length < count) {
        const data = typeof e.data === 'string' ? e.data : '[binary ' + (e.data && e.data.byteLength != null ? e.data.byteLength + ' bytes' : '?') + ']';
        out.frames.push(data.slice(0, 4096));
      }
      if (out.frames.length >= count) { clearTimeout(timer); ws.close(); resolve(); }
    };
    ws.onerror = (e) => {
      out.errors.push(String(e.message || e.type || 'error'));
      clearTimeout(timer);
      resolve();
    };
    ws.onclose = (e) => {
      out.close = { code: e.code, reason: e.reason };
      clearTimeout(timer);
      resolve();
    };
  });
  console.log(JSON.stringify(out, null, 2));
}

module.exports = { main };
if (require.main === module) main();
