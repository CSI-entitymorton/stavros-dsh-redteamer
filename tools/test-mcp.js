#!/usr/bin/env node
// tools/test-mcp.js — smoke test for the chrome-devtools MCP server wired into the agents
// (mcpServers in .agents/*.ts, generated from build-agents.mjs MCP_SERVERS).
//
//   node tools/test-mcp.js [url]        (default url: https://google.com)
//   node tools/test-mcp.js [url] -v     (verbose)
//
// Boots `npx -y chrome-devtools-mcp@latest --headless --isolated` (the exact harness config),
// does the MCP stdio handshake, lists the exposed tools, creates a page, navigates to the URL,
// reads back the page title/content and saves a screenshot under reports/tmp/mcp-test/.
//
// If the default server can't find a Chrome executable (e.g. only Chromium installed) it retries
// once with `--executablePath <chromium>`.
// Exit 0 = server up + navigation verified; exit 1 = failure.
//
// Zero dependencies (node builtins only), consistent with the rest of tools/.
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const URL = process.argv[2] || 'https://google.com';
const VERBOSE = process.argv.includes('-v');
const SERVER_ARGS = ['-y', 'chrome-devtools-mcp@latest', '--headless', '--isolated'];
const PROTOCOLS = ['2025-06-18', '2025-03-26'];

const outDir = path.join(process.cwd(), 'reports', 'tmp', 'mcp-test');
fs.mkdirSync(outDir, { recursive: true });

const log = (s) => { if (VERBOSE) console.log(s); };

function chromeBin() {
  const candidates = ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'chrome'];
  for (const c of candidates) {
    const p = path.join('/usr/bin', c);
    if (fs.existsSync(p)) return p;
  }
  return process.env.CHROME_BIN || '';
}

class McpClient {
  constructor(extraArgs) {
    this.nextId = 1;
    this.pending = new Map();
    this.serverErr = '';
    this.child = spawn('npx', [...SERVER_ARGS, ...extraArgs], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });
    this.child.stdin.on('error', () => {}); // EPIPE after exit
    this.child.stderr.on('data', (d) => { this.serverErr += d.toString(); });
    this.child.stdout.on('data', (d) => this._onData(d.toString()));
    this.child.on('exit', (code, sig) => {
      for (const [, p] of this.pending) p.reject(new Error(`server exited (code=${code}, sig=${sig})`));
      this.pending.clear();
    });
    this.buf = '';
  }

  _onData(chunk) {
    this.buf += chunk;
    let idx;
    while ((idx = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, idx).trim();
      this.buf = this.buf.slice(idx + 1);
      if (line) this._handleLine(line);
    }
  }

  _handleLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (msg.id && this.pending.has(msg.id)) {
      const p = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      if (msg.error) p.reject(new Error(`${p.method}: ${JSON.stringify(msg.error)}`));
      else p.resolve(msg.result);
    }
  }

  send(method, params, opts = {}) {
    const msg = { jsonrpc: '2.0', id: this.nextId++, method, params };
    const timeoutMs = opts.timeoutMs || 120000;
    this.child.stdin.write(JSON.stringify(msg) + '\n');
    return new Promise((resolve, reject) => {
      this.pending.set(msg.id, { resolve, reject, method });
      const t = setTimeout(() => {
        if (this.pending.has(msg.id)) {
          this.pending.delete(msg.id);
          reject(new Error(`timeout after ${timeoutMs}ms waiting for ${method}`));
        }
      }, timeoutMs);
      this.pending.get(msg.id).timer = t;
    });
  }

  async close() {
    this.child.stdin.end();
    await new Promise((r) => setTimeout(r, 500));
    if (this.child.exitCode === null) this.child.kill('SIGKILL');
  }
}

// tools/call wrapper: returns the raw result object, throws on MCP error
async function callTool(c, name, args) {
  return c.send('tools/call', { name, arguments: args }, { timeoutMs: 60000 });
}

// Extracts { ok, text, obj, rawFull } from a tools/call result
function resultText(r) {
  const s = JSON.stringify(r);
  try {
    const parsed = typeof r === 'string' ? JSON.parse(r) : r;
    const content = parsed.content || [];
    const text = content.filter((x) => x.type === 'text').map((x) => x.text).join('\n');
    return { ok: !parsed.isError, text, obj: parsed, rawFull: s, raw: s.slice(0, 800) };
  } catch { return { ok: true, text: '', obj: null, rawFull: s, raw: s.slice(0, 800) }; }
}

// chrome-devtools-mcp (v>=1.x): page id = NUMERIC index. Lo ricava da structuredContent.pages
// ({ id, url, title, selected }) quando presente, altrimenti dal testo markdown
// ("2: Google (https://www.google.com/) [selected]" → 2).
function pageIdFromResult(r) {
  try {
    const parsed = typeof r === 'string' ? JSON.parse(r) : r;
    const pages = parsed && parsed.structuredContent && parsed.structuredContent.pages;
    if (Array.isArray(pages) && pages.length) {
      const sel = pages.find((p) => p.selected);
      const chosen = sel || pages[pages.length - 1];
      if (chosen && typeof chosen.id === 'number') return chosen.id;
    }
  } catch { /* fallback sotto */ }
  try {
    const text = resultText(r).text;
    const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
    const selLine = lines.find((l) => l.includes('[selected]')) || lines[lines.length - 1];
    const m = selLine.match(/^\s*(\d+)\s*:/);
    return m ? Number(m[1]) : null;
  } catch { return null; }
}

async function run(extraArgs) {
  const c = new McpClient(extraArgs);

  let protocol = null;
  for (const pv of PROTOCOLS) {
    try {
      const res = await c.send('initialize', {
        protocolVersion: pv,
        capabilities: { tools: {} },
        clientInfo: { name: 'stavros-mcp-smoke', version: '0.1.0' },
      }, { timeoutMs: 180000 });
      protocol = res.protocolVersion || pv;
      log(`[handshake] initialize OK (protocol ${protocol})`);
      break;
    } catch { /* try next protocol */ }
  }
  if (!protocol) {
    const reason = `initialize failed | server err: ${c.serverErr.slice(0, 500)}`;
    await c.close();
    return { ok: false, reason, chromeMissing: /chrome|executable/i.test(c.serverErr) };
  }
  c.send('notifications/initialized', {}).catch(() => {});

  let tools = [];
  try {
    const res = await c.send('tools/list', {}, { timeoutMs: 30000 });
    tools = (res.tools || []).map((t) => t.name);
    log(`[tools] ${tools.length} tools exposed: ${tools.join(', ')}`);
  } catch (e) {
    const reason = `tools/list failed: ${e.message} | server err: ${c.serverErr.slice(0, 500)}`;
    await c.close();
    return { ok: false, reason, chromeMissing: /chrome|executable/i.test(c.serverErr) };
  }

  const nav = tools.find((t) => /^(navigate|navigate_page)$/.test(t));
  const newPage = tools.includes('new_page');
  const evalTool = tools.find((t) => /^evaluate_script$/.test(t));
  const shotTool = tools.find((t) => /screenshot/i.test(t));
  if (!nav) {
    const reason = `navigate tool missing (tools: ${tools.join(', ') || 'none'}) | server err: ${c.serverErr.slice(0, 500)}`;
    await c.close();
    return { ok: false, reason, chromeMissing: /chrome|executable/i.test(c.serverErr) };
  }

  // --- get/create a page (new_page { url } crea E naviga; l'id arriva in structuredContent.pages) ---
  let pageId = null;
  let chromeMissing = false;
  const npRes = await callTool(c, 'new_page', { url: URL }).catch((e) => ({ error: e.message }));
  const npText = JSON.stringify(npRes);
  log(`[new_page] ${npText.slice(0, 1200)}`);
  if (npRes && !npRes.error && !/could not find|executable/i.test(npText)) {
    pageId = pageIdFromResult(npRes);
  } else if (/could not find|executable/i.test(npText)) {
    chromeMissing = true;
  }
  if (!pageId) {
    // fallback: list_pages sulla pagina esistente (es. pagina di default già aperta)
    const lpRes = await callTool(c, 'list_pages', {}).catch((e) => ({ error: e.message }));
    const lpText = JSON.stringify(lpRes);
    log(`[list_pages] ${lpText.slice(0, 800)}`);
    if (/could not find|executable/i.test(lpText)) chromeMissing = true;
    pageId = pageIdFromResult(lpRes);
  }
  if (!pageId) {
    const reason = `nessuna pagina disponibile (new_page/list_pages falliti) | server err: ${c.serverErr.slice(0, 500)}`;
    await c.close();
    return { ok: false, reason, chromeMissing };
  }
  log(`[page] pageId=${pageId}`);

  // --- navigate (se la pagina non era già stata creata su URL) ---
  let navRaw;
  try {
    navRaw = await callTool(c, nav, { url: URL, pageId }).then(resultText);
    log(`[navigate] ${URL} (${nav}) → ${navRaw.raw}`);
  } catch (e) {
    const reason = `navigate ${URL} failed: ${e.message}`;
    await c.close();
    return { ok: false, reason, chromeMissing };
  }
  if (!navRaw.ok) {
    const reason = `navigate ${URL} errore: ${navRaw.text.slice(0, 500)}`;
    await c.close();
    return { ok: false, reason, chromeMissing };
  }

  await new Promise((r) => setTimeout(r, 4000)); // let the page settle

  // --- title via evaluate_script ---
  let title = '(n/d)';
  if (evalTool) {
    try {
      const r = await callTool(c, evalTool, { function: '() => document.title', pageId }).then(resultText);
      log(`[evaluate_script title] ${r.raw}`);
      if (r.ok) {
        const m = r.text.match(/```json\n"?([^"\n]+)"?\n```/);
        title = m ? m[1].trim() : r.text.slice(0, 120);
      }
    } catch (e) {
      log(`[evaluate_script title] fallito: ${e.message}`);
    }
  }

  // --- content proof: title + body text via evaluate_script ---
  const content = await (async () => {
    if (!evalTool) return { ok: false, note: 'evaluate_script non esposto' };
    try {
      const r = await callTool(c, evalTool, {
        function: '() => ({ title: document.title, body: (document.body ? document.body.innerText : "").slice(0, 500) })',
        pageId,
      }).then(resultText);
      const hasText = r.ok && r.text.length > 50;
      return { ok: hasText, raw: r.raw.slice(0, 400) };
    } catch (e) {
      return { ok: false, note: e.message };
    }
  })();

  // --- screenshot ---
  const shot = await (async () => {
    if (!shotTool) return { saved: false, note: 'screenshot tool non esposto' };
    try {
      const r = await callTool(c, shotTool, { pageId, format: 'png' }).then(resultText);
      // l'immagine arriva come content di tipo "image" → cerca il base64 nell'oggetto completo
      const m = r.rawFull.match(/"data"\s*:\s*"([A-Za-z0-9+/=]+)"/);
      if (!m) return { saved: false, note: `no base64: ${r.raw.slice(0, 200)}` };
      const file = path.join(outDir, `mcp-${Date.now()}.png`);
      fs.writeFileSync(file, Buffer.from(m[1], 'base64'));
      return { saved: true, file };
    } catch (e) {
      return { saved: false, note: e.message };
    }
  })();

  const summary = {
    url: URL,
    protocol,
    serverStarted: true,
    toolsExposed: tools.length,
    pageId,
    title,
    contentVerified: content.ok,
    contentRaw: content.ok ? content.raw : JSON.stringify(content),
    screenshot: shot,
  };

  const ok = content.ok;
  await c.close();
  return { ok, reason: ok ? 'navigate + content verified' : 'content read non verificado', summary, chromeMissing };
}

(async () => {
  log(`[mcp-smoke] target ${URL}, server args: ${SERVER_ARGS.join(' ')}`);

  let res = await run([]);
  // Retry once with explicit executablePath when the server can't find Chrome (e.g. only Chromium)
  if (!res.ok && res.chromeMissing) {
    const bin = chromeBin();
    if (bin) {
      log(`[mcp-smoke] retry con --executablePath ${bin}`);
      res = await run(['--executablePath', bin]);
    }
  }

  if (VERBOSE || !res.ok) console.log(JSON.stringify(res.summary || { reason: res.reason }, null, 2));
  if (res.ok) {
    console.log(`[mcp-smoke] OK — ${URL} caricata (title: ${res.summary.title})`);
    if (res.summary.screenshot.saved) console.log(`[mcp-smoke] screenshot: ${res.summary.screenshot.file}`);
  } else {
    console.error(`[mcp-smoke] FAIL — ${res.reason}`);
    process.exitCode = 1;
  }
})().catch((e) => {
  console.error(`[mcp-smoke] ERRORE — ${e.message}`);
  process.exitCode = 1;
});
