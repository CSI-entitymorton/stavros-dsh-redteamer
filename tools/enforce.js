#!/usr/bin/env node
// Deterministic dangerous-command / rate-discipline scanner for the Stavros harness.
// Ported from SeaOf0/dsh-redteam-model (MIT) — plugins/dsh-sec-enforce/lib/index.js
// (scanDangerous / scanRate), adapted to the project's zero-dependency Node style.
//
//   node tools/enforce.js check <command>   # prints verdict; exit 0 = allowed, 1 = blocked
//   node tools/enforce.js scan <command>    # same, machine-readable JSON on stdout
//
// Fail-closed philosophy (same as scope-guard.js): an uncertain verdict = refusal. Every
// refusal carries a remediation ("downgrade alternative") so the agent can proceed safely.
// The wrapper (tools/run.js) calls scanDangerous + scanRate on every command line AFTER the
// scope check and BEFORE exec; refusals are also appended to reports/tmp/run-audit.jsonl.

'use strict';
const fs = require('fs');
const path = require('path');

/** Conservative high-impact command signatures (minimal set). Returns refusal reason or undefined. */
function scanDangerous(command) {
  const cmd = String(command ?? '');
  const compact = cmd.replace(/\\\n/g, ' ').replace(/\s+/g, ' ');
  if (/(^|[;&|]\s*)rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(\/|~|\$HOME)(\/|\s|$)/.test(compact)) {
    return 'Broad delete (rm touching / or ~ root-level paths) blocked by the deterministic gate: deletions must stay inside the task workspace; if truly needed, list the exact paths, get explicit user approval (ask_user), then delete item by item. Downgrade: cd into the workspace and delete scoped paths one by one, or produce the delete list for the user to run manually.';
  }
  if (/\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b/i.test(compact) && !/^\s*#/.test(compact)) {
    return 'Data-integrity destruction (DROP/TRUNCATE) blocked: the negative list forbids destroying data integrity; for verification use read-only SELECT to reproduce impact, or validate on a lab snapshot with user approval. Downgrade: read-only SELECT reproduction; or verify on a snapshot and note the environment.';
  }
  if (/\b(shutdown\b|reboot\b|systemctl\s+(stop|restart|disable)\b|service\s+\w+\s+(stop|restart)\b|kill\s+-9\s+1\b)/i.test(compact)) {
    return 'Shutdown/reboot/service-kill is a mutating operation, blocked: ask the user first (ask_user with impact and rationale), execute only on approval. Downgrade: collect root cause read-only (systemctl status / logs), put remediation steps in a recommendation list for the user to run.';
  }
  // Funds-related interfaces: write requests (curl/wget POST or -d) to pay/refund/withdraw/order paths
  const fundsUrl = /(pay|refund|withdraw|order|recharge|transfer)[a-z]*\/|[?&](out_trade_no|trade_no|order_id)=/i;
  const isPost = /(\bcurl\b[^|;&]*(-X\s*(POST|PUT)|--data(-raw|-binary)?\s|\s-d\s))|(\bwget\b[^|;&]*--post-data)/i.test(compact);
  if (isPost && fundsUrl.test(compact)) {
    return 'Funds-interface write request (payment/refund/withdrawal/order) blocked: persona hard rule — only build a replay plan to present to the user (ask_user), execute only on explicit approval. Downgrade: generate a read-only replay plan (curl command + expected-response comparison) and present it, do not actually send.';
  }
  return undefined;
}

/** Bare-scan rate signatures (minimal set). Returns refusal reason with the fix, or undefined. */
function scanRate(command) {
  const cmd = String(command ?? '');
  const compact = cmd.replace(/\\\n/g, ' ').replace(/\s+/g, ' ');
  if (/\bnmap\b/.test(compact) && /(-p-\s|--?p\s*1-65535|-p\s*1-65535)/.test(compact) && !/(--max-rate|-T[0-3]\b|--min-rate)/.test(compact)) {
    return 'Full-port nmap without rate control blocked (rate discipline): add --max-rate (e.g. --max-rate 300) or -T2/-T3 and retry; stricter for WAF/production targets. Downgrade: --top-ports 100 for a common-port overview; or passive recon first (subdomains/DNS/public intel) then targeted verification.';
  }
  const massRate = compact.match(/--rate\s+(\d+)/);
  if (/\bmasscan\b/.test(compact) && massRate && Number(massRate[1]) > 1000) {
    return `masscan --rate ${massRate[1]} exceeds the conservative cap (1000), blocked: lower --rate (start at 500) and retry. Downgrade: --rate 500 scoped to the authorized range; or nmap -sS --max-rate 300 targeted scan.`;
  }
  if (/(^|\s|\/)ffuf\b/.test(compact) && /-u\s/.test(compact) && !/-rate\b/.test(compact)) {
    return 'Bare ffuf without -rate blocked: add -rate 50 (conservative default) and retry, or use the wrapped ffuf_fuzz tool (rate discipline / anti-blind-testing / evidence landing built in). Downgrade: -rate 50 retry, or ffuf_fuzz wrapper.';
  }
  return undefined;
}

/** Both scanners; returns the first hit (dangerous wins). */
function scanAll(command) {
  return scanDangerous(command) ?? scanRate(command);
}

function audit(entry) {
  try {
    const dir = path.join(__dirname, '..', 'reports', 'tmp');
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(dir, 'run-audit.jsonl'), JSON.stringify(entry) + '\n');
  } catch { /* audit best-effort */ }
}

function main() {
  const args = process.argv.slice(2);
  const mode = args[0];
  const command = args.slice(1).join(' ');
  if (!command) {
    console.error('usage: node tools/enforce.js <check|scan> <command>');
    process.exit(2);
  }
  const reason = scanAll(command);
  if (mode === 'scan') {
    console.log(JSON.stringify({ command, blocked: !!reason, reason: reason ?? null }));
  } else {
    if (reason) {
      audit({ ts: new Date().toISOString(), gate: 'enforce', verdict: 'blocked', command, reason });
      console.error(`[enforce] BLOCKED: ${reason}`);
      process.exit(1);
    }
    console.log('[enforce] allowed');
  }
}

if (require.main === module) main();

module.exports = { scanDangerous, scanRate, scanAll };
