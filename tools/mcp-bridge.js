#!/usr/bin/env node
// E11 (rimandati) — LEZIONE INVERSA MCP: se serve MCP, ESPONIAMO i NOSTRI tool guardati come
// server MCP (JSON-RPC 2.0 su stdio, SOLO stdlib, zero rete). MAI ingerire broker esterni non
// gated: questo bridge non parla con nessun server esterno — è solo uno strato di ESPOSIZIONE
// delle guardie esistenti (scope-guard/enforce/run.js), deny-by-default.
//
// Tools esposti (whitelist rigida, fail-closed):
//   scope.check  {url}                       → verdetto scope-guard (inScope/cidrInScope/canon)
//   run.dryRun   {bin, args}                 → run.js --dry-run (scope+enforce+key gating, MAI exec)
//   gate.status                              → stato stage-gate (sola lettura)
//   system.info                               → info sul bridge (sola lettura)
// Ondata 6 — Tier 1 read-only (l'agente Freebuff consuma il modello come tool MCP, MAI come
// broker: queste call non eseguono nulla e non aggirano alcun gate):
//   model.snapshot                            → target-model.js snapshot (asset graph, sola lettura)
//   planner.plan                              → next-actions.js plan --json (DRY-RUN, MAI 'run')
//   coverage.gaps                             → coverage-loop.js gaps --json (misura, MAI esecuzione)
//
// Protocollo: UNA richiesta JSON-RPC per riga (newline-delimited JSON) su stdin; risposta su
// stdout. Metodo sconosciuto → -32601; parametri non validi → -32602 (mai fallback silenzioso).
//
// CLI:
//   node tools/mcp-bridge.js            # server stdio (per MCP host / test e2e)
//   node tools/mcp-bridge.js ping       # self-test: risponde a initialize+tools/list
'use strict';
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { spawnSync } = require('child_process');

const WS = path.join(__dirname, '..');

// ─── tool handlers (tutti offline, tutti guardati) ───────────────────────────

function toolScopeCheck(params) {
  const url = params && params.url;
  if (typeof url !== 'string' || !url.trim()) return { error: { code: -32602, message: 'scope.check requires {url}' } };
  const sg = require('./scope-guard');
  const scope = sg.loadScope();
  if (sg.cidrInScope && sg.cidrParseSafe && sg.cidrParseSafe(url)) {
    const v = sg.cidrInScope(url, scope);
    return { result: { content: [{ type: 'text', text: JSON.stringify({ url, ok: !!v.ok, reason: v.reason || null }) }] } };
  }
  const c = sg.canonTarget(/^https?:\/\//i.test(url) ? url : 'http://' + url);
  if (!c.ok) return { result: { content: [{ type: 'text', text: JSON.stringify({ url, ok: false, reason: 'canon: ' + c.reason }) }] } };
  const v = sg.inScope(c.canonical, scope);
  return { result: { content: [{ type: 'text', text: JSON.stringify({ url, canonical: c.canonical, ok: !!v.ok, reason: v.reason || '' }) }] } };
}

// run.dryRun: riusa l'INTERO pipeline di gating (scope+enforce+TOOL_REQUIRES_KEY) tramite
// run.js --dry-run, che NON esegue mai il binario. Zero rete.
function toolRunDryRun(params) {
  const bin = params && params.bin;
  const args = Array.isArray(params && params.args) ? params.args : [];
  if (typeof bin !== 'string' || !bin.trim()) return { error: { code: -32602, message: 'run.dryRun requires {bin, args[]}' } };
  const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'run.js'), '--dry-run', bin, ...args],
    { encoding: 'utf8', env: process.env, timeout: 30000 });
  const out = { bin, args, exit: r.status };
  try { out.verdict = JSON.parse(r.stdout); } catch { out.stdout = r.stdout; out.stderr = r.stderr; }
  return { result: { content: [{ type: 'text', text: JSON.stringify(out) }], blocked: r.status !== 0 } };
}

function toolGateStatus() {
  try {
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', 'gate.js'), 'status', 'host'],
      { encoding: 'utf8', env: process.env, timeout: 30000 });
    return { result: { content: [{ type: 'text', text: r.stdout || r.stderr }] } };
  } catch (e) {
    return { result: { content: [{ type: 'text', text: 'gate status unavailable: ' + e.message }] } };
  }
}

// Ondata 6: read-only Tier 1 tools via CLI spawn (env passthrough: STATE_DB/SCOPE_JSON overridabili
// per i test). Nessuna esecuzione di azioni: planner.plan è il dry-run di default, MAI 'run'.
function spawnReadTool(script, args) {
  try {
    const r = spawnSync(process.execPath, [path.join(WS, 'tools', script), ...args],
      { encoding: 'utf8', env: process.env, timeout: 30000 });
    const text = (r.stdout || r.stderr || '').trim() || JSON.stringify({ ok: false, exit: r.status });
    return { result: { content: [{ type: 'text', text }] } };
  } catch (e) {
    return { result: { content: [{ type: 'text', text: `${script} unavailable: ${e.message}` }] } };
  }
}

function toolModelSnapshot() {
  return spawnReadTool('target-model.js', ['snapshot']);
}

function toolPlannerPlan() {
  return spawnReadTool('next-actions.js', ['plan', '--json']);
}

function toolCoverageGaps() {
  return spawnReadTool('coverage-loop.js', ['gaps', '--json']);
}

function toolSystemInfo() {
  return { result: { content: [{ type: 'text', text: JSON.stringify({ bridge: 'tools/mcp-bridge.js', tools: TOOLS.map((t) => t.name), offline: true, external_brokers: 'none' }) }] } };
}

const TOOLS = [
  { name: 'scope.check', description: 'Scope-guard verdict for a URL/CIDR (deny-by-default)', inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } },
  { name: 'run.dryRun', description: 'run.js --dry-run: full gating verdict (scope+enforce+keys), NEVER executes', inputSchema: { type: 'object', properties: { bin: { type: 'string' }, args: { type: 'array', items: { type: 'string' } } }, required: ['bin'] } },
  { name: 'gate.status', description: 'Stage-gate status (read-only)', inputSchema: { type: 'object', properties: {} } },
  { name: 'model.snapshot', description: 'Asset graph snapshot from target-model (read-only, no execution)', inputSchema: { type: 'object', properties: {} } },
  { name: 'planner.plan', description: 'Finding-driven next actions, DRY-RUN plan only (never executes)', inputSchema: { type: 'object', properties: {} } },
  { name: 'coverage.gaps', description: 'Coverage-driven gaps per host (measure, never executes)', inputSchema: { type: 'object', properties: {} } },
  { name: 'system.info', description: 'Bridge info (read-only)', inputSchema: { type: 'object', properties: {} } },
];

const HANDLERS = {
  'scope.check': toolScopeCheck,
  'run.dryRun': toolRunDryRun,
  'gate.status': toolGateStatus,
  'model.snapshot': toolModelSnapshot,
  'planner.plan': toolPlannerPlan,
  'coverage.gaps': toolCoverageGaps,
  'system.info': toolSystemInfo,
};

// ─── JSON-RPC 2.0 ─────────────────────────────────────────────────────────────

function handleRequest(raw) {
  let req;
  try { req = JSON.parse(raw); } catch {
    return { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } };
  }
  if (!req || typeof req !== 'object' || req.jsonrpc !== '2.0' || typeof req.method !== 'string') {
    return { jsonrpc: '2.0', id: req && req.id !== undefined ? req.id : null, error: { code: -32600, message: 'invalid request' } };
  }
  const id = req.id !== undefined ? req.id : null;
  const params = req.params === undefined ? {} : req.params;
  if (req.method === 'initialize') {
    return { jsonrpc: '2.0', id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'stavros-mcp-bridge', version: '1' } } };
  }
  if (req.method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  }
  if (req.method === 'tools/call') {
    const name = params.name;
    const handler = HANDLERS[name];
    if (!handler) return { jsonrpc: '2.0', id, error: { code: -32601, message: `unknown tool "${name}" (whitelist: ${TOOLS.map((t) => t.name).join(', ')})` } };
    const r = handler(params.arguments);
    if (r.error) return { jsonrpc: '2.0', id, error: r.error };
    return { jsonrpc: '2.0', id, result: r.result };
  }
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${req.method}` } };
}

// ─── server stdio (una riga = una richiesta) ──────────────────────────────────

function serve() {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      process.stdout.write(JSON.stringify(handleRequest(line)) + '\n');
    } catch (e) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'internal error: ' + e.message } }) + '\n');
    }
  });
}

function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === 'ping') {
    const initialize = handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
    const list = handleRequest(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }));
    const ok = initialize.result && Array.isArray(list.result && list.result.tools) && list.result.tools.length === TOOLS.length;
    console.log(JSON.stringify({ ok: !!ok, tools: ok ? list.result.tools.map((t) => t.name) : [] }));
    process.exit(ok ? 0 : 1);
  }
  serve();
}

if (require.main === module) main();
module.exports = { handleRequest, TOOLS, HANDLERS };
