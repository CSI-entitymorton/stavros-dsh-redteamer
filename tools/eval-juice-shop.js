#!/usr/bin/env node
// eval-juice-shop.js — grade Stavros against a local OWASP Juice Shop.
//
// Juice Shop only flips a challenge to `solved` when the actual exploit fires, so this
// harness measures TWO things separately:
//   1. EXPLOITATION — challenges the score board marks solved (ground truth, from /api/Challenges/).
//   2. DETECTION    — vulnerabilities Stavros documented in reports/findings.jsonl, mapped to
//                     Juice Shop challenge keys via a curated signature table.
//
// Detection mapping is heuristic (free-text findings -> challenge keys); the solved count is
// the ground truth. A coarse "technique classes" view is also reported so detection breadth
// is visible even when a finding is not specific enough to pin a single challenge.
//
// Usage (from the StavrosRedTeamer folder):
//   node tools/eval-juice-shop.js snapshot [--base http://localhost:3000] [--out file]
//   node tools/eval-juice-shop.js diff <before.json> <after.json>
//   node tools/eval-juice-shop.js coverage [--findings reports/findings.jsonl] [--offline] [--all]
//   node tools/eval-juice-shop.js report [--baseline <snapshot.json>] [--findings ...]
//
// Zero dependencies (Node built-ins only). Challenge catalog is fetched live from
// GET /api/Challenges/ (unauthenticated) so it always matches the running version.
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPORTS = path.join(ROOT, 'reports');
const DEFAULT_BASE = 'http://localhost:3000';
const CATALOG_CACHE = path.join(REPORTS, 'juice-challenges.json');
const FINDINGS = path.join(REPORTS, 'findings.jsonl');

// ---------------------------------------------------------------------------
// Curated challenge signature table. Signatures are matched (lowercase substring)
// against a finding's title/endpoint/poc/cwe/etc. Keep them SPECIFIC so one finding
// maps to the right challenge(s), not the whole class (the class view handles that).
// ---------------------------------------------------------------------------
const SIGS = {
  // SQLi
  unionSqlInjectionChallenge: ['union select', 'union sql', 'union-based', '/rest/products/search', 'all user credentials'],
  dbSchemaChallenge: ['database schema', 'db schema', 'sqlite_master', 'schema dump', 'sqlite'],
  loginAdminChallenge: ['login admin', 'admin login', 'admin@juice-sh', 'or 1=1', "or '1'='1", "1'='1"],
  loginJimChallenge: ['login jim', 'jim@juice-sh', "jim' or", "jim'--"],
  loginBenderChallenge: ['login bender', 'bender@juice-sh', "bender' or", "bender'--"],
  loginRapperChallenge: ['mc safesearch', 'safesearch', 'rapper'],
  christmasSpecialChallenge: ['christmas special', 'christmas'],
  ephemeralAccountantChallenge: ['ephemeral accountant', 'accountant@juice-sh'],

  // NoSQLi
  noSqlCommandChallenge: ['nosql dos', 'nosql command', 'nosql injection', 'nosqli', '$where', 'sleep injection'],
  noSqlOrdersChallenge: ['nosql exfiltration', 'nosql orders', 'nosql injection', 'nosqli', '$ne', '$gt', '$regex', 'order exfiltration'],
  noSqlReviewsChallenge: ['nosql manipulation', 'nosql reviews', 'nosql injection', 'nosqli', '$ne', '$gt', '$regex'],

  // SSTi / SSRF / XXE
  sstiChallenge: ['ssti', 'server-side template injection', 'template injection', 'angular expression', '{{7*7}}'],
  ssrfChallenge: ['ssrf', 'server-side request forgery'],
  xxeFileDisclosureChallenge: ['xxe data access', 'xxe', 'xml external entity', 'xxe file'],
  xxeDosChallenge: ['xxe dos', 'xxe', 'xml external entity', 'billion laughs'],

  // XSS
  reflectedXssChallenge: ['reflected xss', 'track-order xss', 'reflection in track-order', 'iframe src="javascript:alert(`xss`)'],
  persistedXssFeedbackChallenge: ['server-side xss', 'stored xss', 'persisted xss', 'feedback xss'],
  persistedXssUserChallenge: ['client-side xss', 'stored xss', 'persisted xss', 'username xss'],
  usernameXssChallenge: ['csp bypass', 'username xss', 'csp'],
  restfulXssChallenge: ['api-only xss', 'api xss', 'restful xss', 'product description xss'],
  localXssChallenge: ['dom xss', 'dom-based xss', 'dom based xss', 'local xss'],
  httpHeaderXssChallenge: ['http-header xss', 'header xss', 'last login ip', 'x-forwarded', 'saveLoginIp'],
  videoXssChallenge: ['video xss', 'promo video xss'],
  xssBonusChallenge: ['bonus payload', 'xss bonus'],

  // JWT / crypto
  jwtUnsignedChallenge: ['unsigned jwt', 'alg none', 'alg:none', '"alg":"none"', 'unsigned token'],
  jwtForgedChallenge: ['forged jwt', 'forge jwt', 'alg confusion', 'rs256', 'hs256', 'rsa_lord', 'signed jwt forgery'],
  iacLeakedKeyChallenge: ['login cloud admin', 'cloud admin', 'leaked key', 'iac key'],

  // Authn / session
  passwordHashLeakChallenge: ['password hash', 'hash leak', 'excessive data exposure', 'md5 hash'],
  weakPasswordChallenge: ['password strength', 'weak password'],
  loginSupportChallenge: ['support team', 'support@juice-sh', 'support login'],
  loginAmyChallenge: ['login amy', 'amy@juice-sh', 'credential stuffing', 'password spray'],
  oauthUserPasswordChallenge: ['login bjoern', 'bjoern@juice-sh', 'bjoern oauth', 'oauth'],
  resetPasswordBjoernOwaspChallenge: ['bjoern favorite pet', 'favorite pet', 'bjoern owasp', 'security question'],
  resetPasswordBenderChallenge: ['reset bender', "bender's password", 'bender password'],
  resetPasswordBjoernChallenge: ['reset bjoern', "bjoern's password", 'bjoern password'],
  resetPasswordJimChallenge: ['reset jim', "jim's password", 'jim password', 'security answer'],
  resetPasswordMortyChallenge: ['reset morty', 'morty password', 'morty'],
  resetPasswordUvoginChallenge: ['reset uvogin', 'uvogin password', 'uvogin'],
  changePasswordBenderChallenge: ['change bender', 'change password bender'],
  registerAdminChallenge: ['admin registration', 'register admin', 'role admin'],
  emptyUserRegistration: ['empty user registration', 'register empty'],
  passwordRepeatChallenge: ['repetitive registration', 'password repeat', 'password mismatch', 'passwordrepeat'],
  captchaBypassChallenge: ['captcha bypass', 'captcha'],
  ghostLoginChallenge: ['gdpr data erasure', 'data erasure', 'ghost login', 'account deletion'],
  dataExportChallenge: ['gdpr data theft', 'data export', 'data theft'],
  emailLeakChallenge: ['email leak', 'email enumeration', 'user enumeration'],
  twoFactorAuthUnsafeSecretStorageChallenge: ['two factor', '2fa', 'otp secret', 'totp'],

  // Authz / broken access control
  adminSectionChallenge: ['admin section', 'administration', '/administration', 'admin panel'],
  basketAccessChallenge: ['view basket', 'basket access', 'basket idor', 'idor basket', '/rest/basket'],
  basketManipulateChallenge: ['manipulate basket', 'basket manipulation'],
  changeProductChallenge: ['product tampering', 'change product', 'product description'],
  feedbackChallenge: ['five-star feedback', 'delete feedback', 'feedback access', 'feedback idor'],
  forgedFeedbackChallenge: ['forged feedback', 'feedback forgery', 'feedback userid'],
  forgedReviewChallenge: ['forged review', 'review forgery', 'edit review author'],
  freeDeluxeChallenge: ['deluxe fraud', 'free deluxe', 'deluxe membership'],
  csrfChallenge: ['csrf', 'cross-site request forgery', 'samesite'],

  // File upload
  uploadSizeChallenge: ['upload size', 'file upload size', 'upload pdf'],
  uploadTypeChallenge: ['upload type', 'file upload type', 'upload zip', 'file upload'],

  // Redirect
  redirectChallenge: ['open redirect', 'redirect', 'allowlist bypass'],
  redirectCryptoCurrencyChallenge: ['outdated allowlist', 'open redirect', 'redirect', 'cryptocurrency redirect'],

  // Vulnerable components
  knownVulnerableComponentChallenge: ['vulnerable library', 'known vulnerable component', 'outdated library', 'package.json vulnerability'],
  typosquattingNpmChallenge: ['legacy typosquatting', 'typosquatting', 'epilogue-js', 'npm typosquatting'],
  typosquattingAngularChallenge: ['frontend typosquatting', 'typosquatting', 'cookie-parser', 'angular typosquatting'],
  supplyChainAttackChallenge: ['supply chain attack', 'supply chain'],
  vulnerableDockerImageChallenge: ['vulnerable infrastructure', 'docker image', 'container vulnerability'],
  lfrChallenge: ['local file read', 'lfr', 'path traversal', 'lfi', 'directory traversal'],
  fileWriteChallenge: ['arbitrary file write', 'file write'],

  // Insecure deserialization
  rceChallenge: ['blocked rce', 'rce', 'remote code execution', 'deserialization', 'prototype pollution', '__proto__'],
  rceOccupyChallenge: ['successful rce', 'rce', 'remote code execution', 'deserialization', 'prototype pollution', '__proto__'],
  yamlBombChallenge: ['yaml bomb', 'memory bomb', 'yaml', 'billion laughs'],

  // Sensitive data exposure
  directoryListingChallenge: ['directory listing', 'confidential document', '/ftp', 'acquisitions.md'],
  forgottenDevBackupChallenge: ['forgotten developer backup', 'developer backup', 'package.json.bak'],
  forgottenBackupChallenge: ['forgotten sales backup', 'sales backup', 'coupon backup'],
  exposedCredentialsChallenge: ['exposed credentials', 'hardcoded credentials', 'default credentials', 'admin123'],
  leakedApiKeyChallenge: ['leaked api key', 'hardcoded api key', 'api key', 'algolia'],
  retrieveBlueprintChallenge: ['retrieve blueprint', 'blueprint'],
  geoStalkingMetaChallenge: ['geo stalking', 'geolocation', 'osint', 'exif'],
  geoStalkingVisualChallenge: ['geo stalking', 'geolocation', 'osint', 'exif', 'visual stalking'],

  // Observability / misconfig
  accessLogDisclosureChallenge: ['access log', 'support/logs', 'log disclosure'],
  dlpPasswordSprayingChallenge: ['leaked access logs', 'access log', 'password spray', 'password spraying'],
  dlpPastebinDataLeakChallenge: ['pastebin', 'leaked product', 'unsafe product'],
  exposedMetricsChallenge: ['exposed metrics', 'prometheus', '/metrics'],
  misplacedSignatureFileChallenge: ['misplaced signature', 'signature file', '.pem', 'private key file'],
  misplacedIacFiles: ['misplaced iac', 'iac files', '.tf', 'terraform', 'dockerfile', 'docker-compose'],
  deprecatedInterfaceChallenge: ['deprecated interface', 'b2b interface', 'legacy interface'],
  svgInjectionChallenge: ['svg injection', 'cross-site imaging', 'svg xss', 'svg'],

  // Improper input validation / business logic
  zeroStarsChallenge: ['zero stars', '0 stars', 'rating validation'],
  negativeOrderChallenge: ['negative order', 'negative quantity', 'payback time', 'order manipulation'],
  manipulateClockChallenge: ['expired coupon', 'clock manipulation', 'coupon expiry'],
  forgedCouponChallenge: ['forged coupon', 'coupon forgery'],
  nullByteChallenge: ['null byte', 'poison null', '%00'],
  timingAttackChallenge: ['multiple likes', 'timing attack', 'race condition', 'like race'],

  // Misc but still web-detectable
  errorHandlingChallenge: ['error handling', 'error disclosure', 'stack trace', 'error message'],
  premiumPaywallChallenge: ['premium paywall', 'paywall'],
  weirdCryptoChallenge: ['weird crypto'],
};

// Coarse technique classes — reported separately so detection breadth is visible even
// when a finding can't be pinned to one specific challenge.
const CLASSES = [
  { name: 'SQLi', sigs: ['sql injection', 'sqli', 'union select', 'union-based', 'sqlite'] },
  { name: 'NoSQLi', sigs: ['nosql', 'nosqli', 'mongodb', '$ne', '$where', '$gt', '$regex'] },
  { name: 'XSS', sigs: ['xss', 'cross-site scripting', 'dom xss'] },
  { name: 'SSRF', sigs: ['ssrf', 'server-side request forgery'] },
  { name: 'XXE', sigs: ['xxe', 'xml external entity', 'billion laughs'] },
  { name: 'SSTi', sigs: ['ssti', 'server-side template injection', 'template injection'] },
  { name: 'JWT', sigs: ['jwt', 'json web token', 'alg none', 'alg:none', 'alg confusion', 'rs256', 'hs256'] },
  { name: 'IDOR/BOLA', sigs: ['idor', 'bola', 'broken access', 'broken object level', 'insecure direct object', 'access control'] },
  { name: 'AuthN/Session', sigs: ['password reset', '2fa', 'mfa', 'multi-factor', 'session fixation', 'otp', 'captcha', 'registration', 'login', 'authentication'] },
  { name: 'CSRF', sigs: ['csrf', 'cross-site request forgery', 'samesite'] },
  { name: 'File upload', sigs: ['file upload', 'upload'] },
  { name: 'Open redirect', sigs: ['open redirect', 'redirect'] },
  { name: 'CORS/CSP', sigs: ['cors', 'csp', 'content security policy'] },
  { name: 'Info disclosure', sigs: ['information disclosure', 'sensitive data', 'leak', 'directory listing', 'source map', 'backup'] },
  { name: 'Vuln components', sigs: ['vulnerable library', 'known vulnerable', 'outdated', 'typosquatting', 'supply chain'] },
  { name: 'Deserialization', sigs: ['deserialization', 'prototype pollution', 'yaml', '__proto__'] },
  { name: 'Race/TOCTOU', sigs: ['race condition', 'toctou', 'race'] },
];

// Challenges no web-pentest tool is expected to DETECT (trivia / meta / web3 / LLM /
// steganography / code-only). They don't count against the detection score, but they
// still count on the solved board if Stavros happens to trigger them.
const META = new Set([
  'scoreBoardChallenge', 'privacyPolicyChallenge', 'privacyPolicyProofChallenge',
  'securityPolicyChallenge', 'closeNotificationsChallenge', 'csafChallenge',
  'extraLanguageChallenge', 'tokenSaleChallenge', 'hiddenImageChallenge',
  'easterEggLevelOneChallenge', 'easterEggLevelTwoChallenge', 'continueCodeChallenge',
  'missingEncodingChallenge', 'web3WalletChallenge', 'nftMintChallenge',
  'web3SandboxChallenge', 'chatbotPromptInjectionChallenge', 'chatbotGreedyInjectionChallenge',
  'systemPromptExtractionChallenge',
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.request(new URL(url), { method: 'GET', timeout: 15000 }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        try { resolve(JSON.parse(d)); } catch (e) { reject(new Error('non-JSON response: ' + d.slice(0, 200))); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.end();
  });
}

async function getChallenges(base, offline) {
  if (offline) {
    if (!fs.existsSync(CATALOG_CACHE)) throw new Error('no cached catalog at ' + CATALOG_CACHE + ' and --offline set');
    return JSON.parse(fs.readFileSync(CATALOG_CACHE, 'utf8'));
  }
  const res = await fetchJson(base.replace(/\/$/, '') + '/api/Challenges/');
  const arr = (res && res.data) || [];
  if (!arr.length) throw new Error('empty challenge list from ' + base);
  return arr;
}

function summarize(challenges) {
  const total = challenges.length;
  const solved = challenges.filter((c) => c.solved);
  const byCat = {}, byDiff = {};
  for (const c of challenges) {
    byCat[c.category] = byCat[c.category] || { total: 0, solved: 0 };
    byCat[c.category].total++;
    if (c.solved) byCat[c.category].solved++;
    byDiff[c.difficulty] = byDiff[c.difficulty] || { total: 0, solved: 0 };
    byDiff[c.difficulty].total++;
    if (c.solved) byDiff[c.difficulty].solved++;
  }
  return { total, solvedCount: solved.length, solvedKeys: solved.map((c) => c.key), byCat, byDiff };
}

function loadFindings(p, hostOnly) {
  if (!fs.existsSync(p)) return [];
  const rows = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
  if (!hostOnly) return rows;
  return rows.filter((f) => {
    const h = String(f.host || '').toLowerCase();
    return h.includes('localhost') || h.includes('127.0.0.1') || h.includes('::1');
  });
}

function findingText(f) {
  return [f.title, f.endpoint, f.poc, f.cwe, f.severity, f.impact, f.remediation, f.reference]
    .filter(Boolean).join(' ').toLowerCase();
}

function matchFindings(findings, catalog) {
  const byKey = new Map(catalog.map((c) => [c.key, c]));
  const matched = new Map();
  findings.forEach((f, i) => {
    const text = findingText(f);
    for (const key of Object.keys(SIGS)) {
      if (!byKey.has(key)) continue;
      if (SIGS[key].some((s) => text.includes(s.toLowerCase()))) {
        if (!matched.has(key)) matched.set(key, []);
        matched.get(key).push(i);
      }
    }
  });
  return matched;
}

function detectClasses(findings) {
  const detected = [];
  for (const cls of CLASSES) {
    if (findings.some((f) => cls.sigs.some((s) => findingText(f).includes(s.toLowerCase())))) detected.push(cls.name);
  }
  return detected;
}

function pad(s, n) { s = String(s); return s + ' '.repeat(Math.max(0, n - s.length)); }

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
function cmdSnapshot(args) {
  const base = flag(args, '--base', DEFAULT_BASE);
  const offline = has(args, '--offline');
  const out = flag(args, '--out', path.join(REPORTS, 'juice-score-' + ts() + '.json'));
  return getChallenges(base, offline).then((challenges) => {
    const slim = challenges.map((c) => ({ key: c.key, name: c.name, category: c.category, difficulty: c.difficulty, solved: !!c.solved }));
    fs.writeFileSync(CATALOG_CACHE, JSON.stringify(slim, null, 2) + '\n');
    fs.writeFileSync(out, JSON.stringify(slim, null, 2) + '\n');
    printSummary(summarize(slim));
    console.log('\nsnapshot saved -> ' + out);
  });
}

function cmdDiff(before, after) {
  const b = readSnapshot(before), a = readSnapshot(after);
  const beforeSolved = new Set(b.filter((c) => c.solved).map((c) => c.key));
  const newly = a.filter((c) => c.solved && !beforeSolved.has(c.key));
  console.log('newly solved: ' + newly.length);
  if (newly.length) {
    console.log(pad('difficulty', 12) + pad('category', 30) + 'name');
    for (const c of newly.sort((x, y) => x.difficulty - y.difficulty)) {
      console.log(pad(c.difficulty, 12) + pad(c.category, 30) + c.name);
    }
    const g = {};
    for (const c of newly) { g[c.category] = g[c.category] || []; g[c.category].push(c.name); }
    console.log('\nby category:');
    for (const k of Object.keys(g).sort()) console.log('  ' + k + ': ' + g[k].length);
  }
}

function cmdCoverage(args) {
  const offline = has(args, '--offline');
  const base = flag(args, '--base', DEFAULT_BASE);
  const hostOnly = !has(args, '--all');
  const findings = loadFindings(flag(args, '--findings', FINDINGS), hostOnly);
  return getChallenges(base, offline).then((challenges) => {
    const matched = matchFindings(findings, challenges);
    const byKey = new Map(challenges.map((c) => [c.key, c]));
    const scorable = challenges.filter((c) => !META.has(c.key));
    const scorableKeys = new Set(scorable.map((c) => c.key));
    const detectedKeys = new Set([...matched.keys()].filter((k) => scorableKeys.has(k)));
    const solvedKeys = new Set(challenges.filter((c) => c.solved).map((c) => c.key));
    const classes = detectClasses(findings);

    console.log('findings (Juice Shop host): ' + findings.length);
    console.log('technique classes detected: ' + (classes.length ? classes.join(', ') : '(none)'));
    console.log('challenges detected: ' + detectedKeys.size + ' / ' + scorable.length + ' scorable');
    console.log('challenges solved  : ' + [...solvedKeys].filter((k) => scorableKeys.has(k)).length + ' / ' + scorable.length + ' scorable');

    const detectedAndSolved = [...detectedKeys].filter((k) => solvedKeys.has(k));
    const detectedNotSolved = [...detectedKeys].filter((k) => !solvedKeys.has(k));
    const solvedNotDetected = [...solvedKeys].filter((k) => scorableKeys.has(k) && !detectedKeys.has(k));

    console.log('\n  detected & solved   : ' + detectedAndSolved.length);
    console.log('  detected, not solved: ' + detectedNotSolved.length);
    console.log('  solved, not detected: ' + solvedNotDetected.length);

    if (detectedKeys.size) {
      console.log('\ndetected challenges by category:');
      const g = {};
      for (const k of detectedKeys) {
        const c = byKey.get(k);
        g[c.category] = g[c.category] || [];
        g[c.category].push((c.solved ? '[solved] ' : '') + c.name);
      }
      for (const cat of Object.keys(g).sort()) {
        console.log('  ' + cat + ' (' + g[cat].length + '):');
        for (const n of g[cat].sort()) console.log('    - ' + n);
      }
    }
    if (detectedNotSolved.length) {
      console.log('\ndetected but NOT solved (found it, didn\u2019t exploit it):');
      for (const k of detectedNotSolved) {
        const c = byKey.get(k);
        console.log('  - [' + c.difficulty + '] ' + c.name + '  (' + c.category + ')');
      }
    }
  });
}

function cmdReport(args) {
  const base = flag(args, '--base', DEFAULT_BASE);
  const hostOnly = !has(args, '--all');
  const baseline = flag(args, '--baseline', null);
  const findingsPath = flag(args, '--findings', FINDINGS);
  const offline = has(args, '--offline');
  return getChallenges(base, offline).then((challenges) => {
    const byKey = new Map(challenges.map((c) => [c.key, c]));
    const findings = loadFindings(findingsPath, hostOnly);
    const matched = matchFindings(findings, challenges);
    const scorable = challenges.filter((c) => !META.has(c.key));
    const scorableKeys = new Set(scorable.map((c) => c.key));
    const detectedKeys = new Set([...matched.keys()].filter((k) => scorableKeys.has(k)));
    const solvedKeys = new Set(challenges.filter((c) => c.solved).map((c) => c.key));
    const solvedScorable = [...solvedKeys].filter((k) => scorableKeys.has(k));
    const detectedAndSolved = [...detectedKeys].filter((k) => solvedKeys.has(k));
    const detectedNotSolved = [...detectedKeys].filter((k) => !solvedKeys.has(k));
    const solvedNotDetected = solvedScorable.filter((k) => !detectedKeys.has(k));
    const classes = detectClasses(findings);

    let newly = null;
    if (baseline) {
      const b = readSnapshot(baseline);
      const beforeSolved = new Set(b.filter((c) => c.solved).map((c) => c.key));
      newly = challenges.filter((c) => c.solved && !beforeSolved.has(c.key));
    }

    const o = (s) => console.log(s);
    o('Juice Shop evaluation — ' + new Date().toISOString());
    o('=============================================================');
    o('DETECTION (Stavros found it)');
    o('  findings recorded   : ' + findings.length);
    o('  technique classes   : ' + (classes.length ? classes.join(', ') : '(none)'));
    o('  challenges detected : ' + detectedKeys.size + ' / ' + scorable.length + ' scorable (' + Math.round(detectedKeys.size / scorable.length * 100) + '%)');
    o('EXPLOITATION (Juice Shop marked it solved)');
    o('  challenges solved   : ' + solvedScorable.length + ' / ' + scorable.length + ' scorable (' + Math.round(solvedScorable.length / scorable.length * 100) + '%)');
    o('OVERLAP');
    o('  detected & solved   : ' + detectedAndSolved.length);
    o('  detected, not solved: ' + detectedNotSolved.length);
    o('  solved, not detected: ' + solvedNotDetected.length);
    if (newly) {
      o('  newly solved vs baseline: ' + newly.length);
      for (const c of newly.sort((x, y) => x.difficulty - y.difficulty)) o('    - [' + c.difficulty + '] ' + c.name + ' (' + c.category + ')');
    }
    o('  (excluded from "scorable": ' + META.size + ' meta/web3/LLM/stego challenges)');

    const md = [];
    md.push('# Juice Shop evaluation report');
    md.push('');
    md.push('Generated: ' + new Date().toISOString());
    md.push('');
    md.push('> Detection mapping is heuristic; the **solved** count is the ground truth.');
    md.push('');
    md.push('| Metric | Value |');
    md.push('|---|---|');
    md.push('| Findings recorded | ' + findings.length + ' |');
    md.push('| Technique classes detected | ' + (classes.length ? classes.join(', ') : '—') + ' |');
    md.push('| Challenges detected | ' + detectedKeys.size + ' / ' + scorable.length + ' (' + Math.round(detectedKeys.size / scorable.length * 100) + '%) |');
    md.push('| Challenges solved | ' + solvedScorable.length + ' / ' + scorable.length + ' (' + Math.round(solvedScorable.length / scorable.length * 100) + '%) |');
    md.push('| Detected & solved | ' + detectedAndSolved.length + ' |');
    md.push('| Detected, not solved | ' + detectedNotSolved.length + ' |');
    md.push('| Solved, not detected | ' + solvedNotDetected.length + ' |');
    md.push('');
    if (detectedNotSolved.length) {
      md.push('## Detected but not solved');
      md.push('');
      for (const k of detectedNotSolved) { const c = byKey.get(k); md.push('- **' + c.name + '** (' + c.category + ', diff ' + c.difficulty + ')'); }
      md.push('');
    }
    if (solvedNotDetected.length) {
      md.push('## Solved but no matching finding');
      md.push('');
      for (const k of solvedNotDetected) { const c = byKey.get(k); md.push('- **' + c.name + '** (' + c.category + ')'); }
      md.push('');
    }
    const out = path.join(REPORTS, 'juice-eval-report.md');
    fs.writeFileSync(out, md.join('\n'));
    o('\nreport written -> ' + out);
  });
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function flag(args, name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
}
function has(args, name) { return args.includes(name); }
function ts() { return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19); }
function readSnapshot(p) {
  if (!fs.existsSync(p)) { console.error('no such file: ' + p); process.exit(1); }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}
function printSummary(s) {
  console.log('total ' + s.total + ' | solved ' + s.solvedCount);
  console.log(pad('difficulty', 12) + 'solved/total');
  for (const d of Object.keys(s.byDiff).map(Number).sort((a, b) => a - b)) {
    console.log(pad(String(d), 12) + s.byDiff[d].solved + '/' + s.byDiff[d].total);
  }
  console.log('\nby category:');
  for (const c of Object.keys(s.byCat).sort()) {
    console.log('  ' + pad(c, 32) + s.byCat[c].solved + '/' + s.byCat[c].total);
  }
}

const cmd = process.argv[2];
const rest = process.argv.slice(3);
const run = (() => {
  if (cmd === 'snapshot') return cmdSnapshot(rest);
  if (cmd === 'diff') { if (rest.length < 2) { console.error('usage: diff <before.json> <after.json>'); process.exit(2); } return cmdDiff(rest[0], rest[1]); }
  if (cmd === 'coverage') return cmdCoverage(rest);
  if (cmd === 'report') return cmdReport(rest);
  console.error('usage: node tools/eval-juice-shop.js <snapshot|diff|coverage|report> [options]');
  process.exit(2);
})();

Promise.resolve(run).then(() => process.exit(0)).catch((e) => { console.error('ERROR: ' + (e.message || e)); process.exit(1); });
