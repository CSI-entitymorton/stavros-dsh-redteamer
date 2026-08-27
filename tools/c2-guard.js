#!/usr/bin/env node
// Hard action-tier guard for C2 commands. Maps a Sliver/Metasploit command to an action
// class, then a tier: 'auto' (allowed) or 'confirm' (refused unless --confirm is passed).
// Unknown commands fail closed to 'confirm'. Pivot commands' destination hosts are extracted
// and scope-checked (reusing scope-guard + run.js host extraction).
//
// ponytail: keyword table, not a real parser. A command that hides a host/action in an exotic
// flag can be misclassified. Upgrade path: parse each front-end's command grammar. Fail-closed
// default keeps a miss on the safe side (confirm, not auto).
const { inScope, cidrInScope } = require('./scope-guard');
const { hostsFromText, isCidr } = require('./run');

// command keyword -> action class. First match wins.
const RULES = [
  [/\b(persist|persistence|autorun|service[- ]?create|schtask|crontab|startup|wmi[- ]?event)\b/i, 'persist'],
  // ssh/scp/sftp are LATERAL only when aimed at another box (user@host, bare IPv4,
  // a remote host: target for scp/sftp, or -h/-i/-p style flags); plain mentions
  // inside paths (~/.ssh/id_rsa) stay loot_read.
  [/\b(psexec|winrm|smbexec|wmiexec|rdp|pivot|portfwd|route add|lateral|jump)\b|\b(?:scp|sftp)\s+[^;\n|&]*?(?:\S+@\S+|\d{1,3}(?:\.\d{1,3}){3}):|\bssh\s+(?:-\S+\s+\S+\s+)*\S+@|\bssh\s+\d{1,3}(?:\.\d{1,3}){3}\b|\bssh\s+-{1,2}[hip]\b/i, 'lateral'],
  [/\b(hashdump|lsadump|sam|mimikatz|logonpasswords|dcsync|secretsdump|creds? dump|kerberoast)\b/i, 'cred_dump'],
  [/\b(exfil|exfiltrate|upload .* c2|tar .* \| )\b/i, 'exfil'],
  [/\b(rm -rf|del \/f|format |shutdown|reboot|mkfs|dd if=|drop table|wevtutil cl)\b/i, 'destructive'],
  [/\b(download|cat|type |read |screenshot|keylog dump|loot)\b/i, 'loot_read'],
  // `sudo -l` / `sudo --list` (read-only flags BEFORE it, nothing dangerous after, no
  // chaining) is a CHECK. Anything else starting with sudo is treated as an attempt.
  [/^\s*sudo\s+(?:-{1,2}[a-z]+\s+)*-{1,2}l(?:ist)?\s*(?:2>&1)?\s*$/i, 'privesc_check'],
  // privesc EXPLOIT verbs must be matched BEFORE the generic privesc_check rule.
  // Any other `sudo <cmd>` is an exploitation attempt, not a listing.
  [/\b(getsystem|pwnkit|dirtycow|dirtypipe|cve-\d{4}-\d+|nsenter|unshare|setcap|chmod\s+\+[sx]|mount\s+-o\s+remount|sudo\s+(?!-l\b|-n\b|-{1,2}list\b)\S+)\b/i, 'privesc_exploit'],
  [/\b(getuid|getprivs|whoami \/priv|winpeas|linpeas|seatbelt|priv|escalat)\b/i, 'privesc_check'],
  [/\b(ps|ls|dir|pwd|ifconfig|ipconfig|netstat|whoami|hostname|env|info|sysinfo|arp|route print|id|uname|ver)\b/i, 'enum'],
];

function loadTiers(scope) {
  const ho = (scope && scope.host_ops) || {};
  return {
    auto: new Set(ho.auto || ['enum', 'loot_read', 'privesc_check']),
    confirm: new Set(ho.confirm || ['persist', 'lateral', 'exfil', 'cred_dump', 'privesc_exploit', 'destructive']),
  };
}

function classifyRaw(command) {
  for (const [re, cls] of RULES) if (re.test(command)) return cls;
  return null; // unknown
}

function classify(command, scope) {
  const tiers = loadTiers(scope);
  const cls = classifyRaw(command);
  if (cls && tiers.auto.has(cls)) return { actionClass: cls, tier: 'auto' };
  // known-confirm OR unknown -> confirm (fail closed)
  return { actionClass: cls || 'unknown', tier: 'confirm' };
}

function enforce(command, opts, scope) {
  const { tier, actionClass } = classify(command, scope);
  if (tier === 'auto') return { ok: true, actionClass, tier };
  if (opts && opts.confirm && String(opts.confirm).trim())
    return { ok: true, actionClass, tier, confirmed: true };
  return { ok: false, reason: `action '${actionClass}' is confirm-tier: pass --confirm "<reason>" (requires explicit in-session user approval)`, actionClass, tier };
}

// Extract candidate destination hosts (IP/hostname) from a lateral command's tokens.
function pivotTargets(command) {
  return [...hostsFromText(command.replace(/\s+/g, '\n'))];
}
function pivotInScope(command, scope) {
  const bad = pivotTargets(command).filter((h) =>
    isCidr(h) ? !cidrInScope(h, scope).ok : !inScope('http://' + h, scope).ok);
  return bad.length ? { ok: false, badHosts: bad } : { ok: true };
}

module.exports = { classify, enforce, pivotTargets, pivotInScope, loadTiers };
