#!/usr/bin/env node
// Attack-chain builder — turns the flat findings.jsonl list into exploitable chains.
// The harness's best real-world results (OTP-redirect ATO, leaked-key GraphQL BOLA) were
// CHAINS assembled by hand; this makes chain discovery deterministic.
//   node tools/chain.js [--file reports/findings.jsonl] [--host <h>]
// Groups findings by host and applies keyword rules to pair findings that amplify each other.
const fs = require('fs');
const path = require('path');

// Order matters: authz first (token-mint/IDOR findings must not be stolen by the 'leak' class),
// and the leak class requires leak CONTEXT (bare 'token' is too ambiguous).
const CLASS = [
  // Host-domain classes FIRST, with narrow host-specific vocabulary so they don't steal web
  // findings (the authz rule below deliberately owns generic 'escalation'/'priv-esc'/'takeover').
  [/\b(remote code execution|deserial|meterpreter|reverse shell|initial access|foothold)\b/i, 'foothold'],
  [/\b(suid|sudo|unquoted service|alwaysinstallelevated|getsystem|linpeas|winpeas|kernel exploit|writable service)\b|local privilege escalation/i, 'privesc'],
  [/\b(lateral|pass-the-hash|pass the hash|psexec|kerberoast|dcsync|pivot to|domain admin)\b/i, 'lateral'],
  [/idor|bola|broken access|missing auth|unauth|authori[sz]ed|escalat|priv-?esc|impersonat|takeover|token mint|sso|auth bypass/i, 'authz'],
  [/login|rate limit|lockout|brute|spray|enumerat|reset|otp|fixation|session/i, 'authn'],
  [/leak|hardcoded|secret|api[ _-]?key|credential|source map|bundle|expos|private key|access[ _-]?token/i, 'leak'],
  [/sqli|sql injection|xss|ssrf|command|template|injection|rce/i, 'injection'],
  [/swagger|introspection|header|cors|disclos|error|info/i, 'info'],
];

function classify(title) {
  for (const [re, name] of CLASS) if (re.test(title)) return name;
  return 'other';
}

function sevRank(f) {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 }[f.severity] || 0;
}

// Pair-based chain detection per host. Returns [{name, findings:[titles], reasoning}].
function buildChains(findings) {
  const byHost = {};
  for (const f of findings) {
    const h = f.host || '?';
    (byHost[h] = byHost[h] || []).push(f);
  }
  const out = [];
  for (const [host, fs] of Object.entries(byHost)) {
    const hosts = { leak: [], authz: [], authn: [], injection: [], foothold: [], privesc: [], lateral: [], info: [], other: [] };
    for (const f of fs) hosts[classify(f.title)].push(f);
    const chains = [];
    const pick = (arr) => arr.map((f) => f.title + ' [' + f.severity + ']').slice(0, 3);

    if (hosts.leak.length && hosts.authz.length)
      chains.push({
        name: 'Leaked-secret authorization bypass',
        reasoning: 'A leaked secret (bundle/source-map/hardcoded key) plus a broken-authorization finding on the same host often combine: the leaked key satisfies the "auth" the broken check relies on.',
        findings: [...pick(hosts.leak), ...pick(hosts.authz)],
      });
    if (hosts.leak.length && hosts.authn.length)
      chains.push({
        name: 'Credential-driven auth attack surface',
        reasoning: 'A leaked credential plus an auth weakness (no rate limit / oracle / OTP flaw) enables password spraying or OTP-redirect takeover.',
        findings: [...pick(hosts.leak), ...pick(hosts.authn)],
      });
    if (hosts.authz.length >= 2)
      chains.push({
        name: 'Authorization chain (escalation path)',
        reasoning: 'Two or more distinct access-control failures can be walked in sequence (enumerate -> impersonate -> escalate).',
        findings: pick(hosts.authz),
      });
    if (hosts.leak.length && hosts.injection.length)
      chains.push({
        name: 'Amplified injection',
        reasoning: 'A leaked secret plus an injection finding on the same host: the injection gains more value once authenticated with the leaked key.',
        findings: [...pick(hosts.leak), ...pick(hosts.injection)],
      });
    if ((hosts.foothold.length || hosts.injection.length) && hosts.privesc.length)
      chains.push({
        name: 'Foothold to host takeover (escalation)',
        reasoning: 'A code-exec/foothold finding plus a local privilege-escalation vector on the same host: land, then escalate to SYSTEM/root.',
        findings: [...pick(hosts.foothold), ...pick(hosts.injection), ...pick(hosts.privesc)],
      });
    if ((hosts.privesc.length || hosts.foothold.length) && hosts.lateral.length)
      chains.push({
        name: 'Host takeover to lateral movement',
        reasoning: 'Elevated access on one host plus a lateral finding: pivot to adjacent in-scope hosts / domain.',
        findings: [...pick(hosts.privesc), ...pick(hosts.lateral)],
      });
    const unauthMint = hosts.authz.filter((f) => /unauth|no auth|any|anonymous|without|drop/i.test(f.title + ' ' + (f.poc || '')));
    if (unauthMint.length && hosts.authz.length >= 2)
      chains.push({
        name: 'Unauthenticated impersonation',
        reasoning: 'A token-minting / identity-binding flaw reachable without (or with any) auth turns other access-control findings into full impersonation.',
        findings: pick(unauthMint),
      });
    const crits = fs.filter((f) => sevRank(f) >= 5);
    if (crits.length >= 2)
      chains.push({
        name: 'Critical cluster',
        reasoning: crits.length + ' Critical findings on one host — verify whether they share a root cause (fixing one may close the others).',
        findings: pick(crits),
      });
    if (chains.length) out.push({ host, severity_top: Math.max(...fs.map(sevRank)), chain_count: chains.length, chains });
  }
  out.sort((a, b) => b.severity_top - a.severity_top);
  return out;
}

const argv = process.argv.slice(2);
if (require.main === module) {
  const file = argv[argv.indexOf('--file') + 1] || path.join(__dirname, '..', 'reports', 'findings.jsonl');
  const hostFilter = argv[argv.indexOf('--host') + 1];
  if (!fs.existsSync(file)) {
    console.error(JSON.stringify({ error: 'findings file not found: ' + file }));
    process.exit(1);
  }
  const findings = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  let chains = buildChains(findings);
  if (hostFilter) chains = chains.filter((c) => c.host === hostFilter);
  console.log(JSON.stringify({ findings: findings.length, chains }, null, 2));
}

module.exports = { buildChains, classify };
