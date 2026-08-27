#!/usr/bin/env node
// Vendor mirror for third-party PoC/tool archives (repo-vet churchofmalware plan, QW2).
// Downloads immutable per-SHA snapshots of vetted repos from the Gitea instance into
// vendor/mirror/<repo>/<sha>.zip and keeps a hash-pinned manifest. ZIP archives are NEVER
// extracted by this tool and never executed — they are reference material; an operator who
// needs one file unzips it manually inside an isolated lab.
//
//   node tools/vendor-mirror.js pull <owner>/<repo> [--ref <branch>] [--instance <url>]
//   node tools/vendor-mirror.js verify [--manifest <file>]      # re-hash every archive
//   node tools/vendor-mirror.js list-zip <archive.zip>          # central-directory listing
//   node tools/vendor-mirror.js index-poc                       # build vendor/poc-archive/index.json
//
// index-poc scans the pinned PoC-archive zips' file NAMES only (no decompression) and emits
// the CVE-keyed index that tools/searchsploit.js merges as its second local source.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_INSTANCE = process.env.VENDOR_INSTANCE || 'https://git.churchofmalware.org';
const DEFAULT_ROOT = path.join(__dirname, '..', 'vendor', 'mirror');
const POC_REPOS = ['K3ysTr0K3R/CVE-Exploits-Archive', 'seasecresponse/Sea-Sec-Response'];
const MANIFEST = () => path.join(mirrorRoot(), 'MANIFEST.jsonl');

function mirrorRoot() {
  return process.env.VENDOR_MIRROR_DIR || DEFAULT_ROOT;
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function api(ctx, instance, urlPath) {
  const fetchFn = ctx.fetch || global.fetch;
  const r = await fetchFn(instance.replace(/\/+$/, '') + urlPath, { headers: { 'User-Agent': 'stavros-vendor-mirror' } });
  if (!r.ok) throw new Error('HTTP ' + r.status + ' for ' + urlPath);
  return r.json();
}

async function fetchBytes(ctx, url) {
  const fetchFn = ctx.fetch || global.fetch;
  const r = await fetchFn(url, { headers: { 'User-Agent': 'stavros-vendor-mirror' } });
  if (!r.ok) throw new Error('HTTP ' + r.status + ' for ' + url);
  return Buffer.from(await r.arrayBuffer());
}

// Resolve owner/repo@ref to the commit SHA of that branch (ref defaults to default_branch).
async function resolveSha(ctx, instance, slug, ref) {
  const repo = await api(ctx, instance, '/api/v1/repos/' + slug);
  const branchName = ref || repo.default_branch || 'main';
  if (ref && /^[0-9a-f]{40}$/i.test(ref)) return { sha: ref, branch: null };
  const branch = await api(ctx, instance, '/api/v1/repos/' + slug + '/branches/' + encodeURIComponent(branchName));
  return { sha: branch.commit.id, branch: branchName };
}

function appendManifest(entry) {
  fs.mkdirSync(path.dirname(MANIFEST()), { recursive: true });
  fs.appendFileSync(MANIFEST(), JSON.stringify(entry) + '\n');
}

function readManifest(file) {
  const f = file || MANIFEST();
  let text = '';
  try { text = fs.readFileSync(f, 'utf8'); } catch { return []; }
  return text.split(/\r?\n/).filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);
}

// Pull one repo snapshot: pin SHA -> download archive zip -> record manifest entry.
async function pull(ctx, slug, opts) {
  opts = opts || {};
  ctx = ctx || {};
  const instance = opts.instance || DEFAULT_INSTANCE;
  const root = opts.root || mirrorRoot();
  const [owner, repo] = String(slug).split('/');
  if (!owner || !repo || !/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) {
    return { ok: false, error: 'invalid repo slug: ' + slug };
  }
  try {
    const { sha, branch } = await resolveSha(ctx, instance, slug, opts.ref);
    const dir = path.join(root, repo);
    const file = path.join(dir, sha + '.zip');
    if (fs.existsSync(file)) {
      return { ok: true, cached: true, repo, sha, file, sha256: sha256(fs.readFileSync(file)) };
    }
    const buf = await fetchBytes(ctx, instance.replace(/\/+$/, '') + '/api/v1/repos/' + slug + '/archive/' + sha + '.zip');
    // sanity: must start with a plausible archive signature (PK\x03\x04 or PK\x05\x06 empty)
    if (!(buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b)) {
      return { ok: false, error: 'downloaded bytes are not a zip archive' };
    }
    fs.mkdirSync(dir, { recursive: true });
    const tmp = file + '.' + process.pid;
    fs.writeFileSync(tmp, buf);
    fs.renameSync(tmp, file);
    const entry = {
      repo, owner, instance,
      branch: branch || null,
      sha,
      file: path.relative(path.dirname(root), file),
      bytes: buf.length,
      sha256: sha256(buf),
      pulled_at: new Date().toISOString(),
    };
    appendManifest(entry);
    return { ok: true, ...entry };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// Re-hash every manifest entry; any mismatch or missing file is reported (fail loudly).
function verify(opts) {
  opts = opts || {};
  const entries = readManifest(opts.manifest);
  const results = entries.map((e) => {
    const file = e.file ? path.join(path.dirname(mirrorRoot()), e.file) : null;
    if (!file || !fs.existsSync(file)) return { repo: e.repo, sha: e.sha, ok: false, error: 'missing archive file' };
    const actual = sha256(fs.readFileSync(file));
    return { repo: e.repo, sha: e.sha, ok: actual === e.sha256, expected: e.sha256, actual };
  });
  return { checked: results.length, ok: results.every((r) => r.ok), results };
}

// ---- minimal ZIP central-directory reader (names only — NO decompression, NO extraction) ----
// Parses the End Of Central Directory record, then walks central directory entries to collect
// file names. Malformed/truncated input returns [] instead of throwing (bomb-safe: we never
// inflate, so a zip bomb costs nothing here).
function listZipNames(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  const EOCD = 0x06054b50;
  const CDE = 0x02014b50;
  if (b.length < 22 || b[0] !== 0x50 || b[1] !== 0x4b) return [];
  // locate EOCD scanning backwards over a max 64KiB comment
  let eocd = -1;
  const minPos = Math.max(0, b.length - 22 - 65535);
  for (let i = b.length - 22; i >= minPos; i--) {
    if (b.readUInt32LE(i) === EOCD) { eocd = i; break; }
  }
  if (eocd < 0) return [];
  let count = b.readUInt16LE(eocd + 10);
  let pos = b.readUInt32LE(eocd + 16); // offset of central directory
  const names = [];
  while (count-- > 0) {
    if (pos + 46 > b.length || b.readUInt32LE(pos) !== CDE) break;
    const nameLen = b.readUInt16LE(pos + 28);
    const extraLen = b.readUInt16LE(pos + 30);
    const commentLen = b.readUInt16LE(pos + 32);
    names.push(b.toString('utf8', pos + 46, Math.min(pos + 46 + nameLen, b.length)));
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

const CVE_PATH_RE = /CVE-\d{4}-\d{4,}/gi;

// Build vendor/poc-archive/index.json from every pinned zip of the PoC repos: file paths +
// which CVE ids each path mentions. Purely name-based; content stays sealed in the zip.
function indexPoc(opts) {
  opts = opts || {};
  const root = opts.root || mirrorRoot();
  const out = { generated_at: new Date().toISOString(), archives: [], note: 'paths extracted from zip central directories; archives stay sealed in vendor/mirror (hash-pinned), open them only in an isolated lab' };
  const wanted = opts.repos || POC_REPOS;
  for (const slug of wanted) {
    const repo = slug.split('/')[1];
    const dir = path.join(root, repo);
    let files = [];
    try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.zip')); } catch {}
    for (const f of files.sort().reverse()) { // newest sha first
      const full = path.join(dir, f);
      const buf = fs.readFileSync(full);
      const entries = listZipNames(buf)
        .filter((n) => !n.endsWith('/'))
        .map((n) => {
          const cves = [...new Set((n.match(CVE_PATH_RE) || []).map((c) => c.toUpperCase()))];
          return cves.length ? { path: n, cves } : null;
        })
        .filter(Boolean);
      out.archives.push({
        repo, instance: DEFAULT_INSTANCE,
        file: path.relative(path.dirname(root), full),
        sha256: sha256(buf),
        entries,
      });
      break; // only index the most recent snapshot per repo
    }
  }
  const idxFile = opts.indexFile || path.join(__dirname, '..', 'vendor', 'poc-archive', 'index.json');
  fs.mkdirSync(path.dirname(idxFile), { recursive: true });
  fs.writeFileSync(idxFile, JSON.stringify(out, null, 2));
  return { ok: true, file: idxFile, archives: out.archives.length, indexed_paths: out.archives.reduce((n, a) => n + a.entries.length, 0) };
}

// Query the PoC index (used by searchsploit.js): term may be a CVE id or a path substring.
function queryPocIndex(term, indexFile) {
  const f = indexFile || path.join(__dirname, '..', 'vendor', 'poc-archive', 'index.json');
  const idx = (() => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } })();
  if (!idx || !Array.isArray(idx.archives)) return [];
  const t = String(term == null ? '' : term).trim();
  if (!t) return [];
  const cve = /^CVE-?/i.test(t) ? t.toUpperCase().replace(/^CVE-?/, 'CVE-') : null;
  const needle = t.toLowerCase();
  const hits = [];
  for (const a of idx.archives) {
    for (const e of a.entries) {
      const match = (cve && e.cves.includes(cve)) || (!cve && e.path.toLowerCase().includes(needle));
      if (match) hits.push({ repo: a.repo, path: e.path, cves: e.cves, archive: a.file, sha256: a.sha256 });
    }
  }
  return hits.slice(0, 50);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const flag = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  if (cmd === 'pull') {
    const slug = argv[1];
    if (!slug || !slug.includes('/')) { console.error('usage: vendor-mirror.js pull <owner>/<repo> [--ref <branch>]'); process.exit(2); }
    const r = await pull({}, slug, { ref: flag('--ref'), instance: flag('--instance') });
    console.log(JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : 1);
  }
  if (cmd === 'verify') {
    const r = verify({ manifest: flag('--manifest') });
    console.log(JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : 1);
  }
  if (cmd === 'list-zip') {
    const file = argv[1];
    if (!file) { console.error('usage: vendor-mirror.js list-zip <archive.zip>'); process.exit(2); }
    console.log(JSON.stringify({ file, entries: listZipNames(fs.readFileSync(file)) }, null, 2));
    process.exit(0);
  }
  if (cmd === 'index-poc') {
    console.log(JSON.stringify(indexPoc({}), null, 2));
    process.exit(0);
  }
  console.error('usage: vendor-mirror.js pull|verify|list-zip|index-poc ...');
  process.exit(2);
}
if (require.main === module) main();

module.exports = { pull, verify, readManifest, listZipNames, indexPoc, queryPocIndex, resolveSha, sha256, POC_REPOS, DEFAULT_INSTANCE };
