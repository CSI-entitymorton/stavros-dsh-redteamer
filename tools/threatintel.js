#!/usr/bin/env node
// Live CVE threat-intel enrichment: NVD API v2 + CISA KEV + FIRST EPSS, cached on disk.
// Zero-dependency (global fetch, Node >= 22). Upgrades the offline-only maps in epss.js:
//   node tools/threatintel.js refresh CVE-2021-44228 [CVE-...]   # fetch NVD+EPSS+KEV -> cache
//   node tools/threatintel.js lookup  CVE-2021-44228 [--refresh] # merged intel from cache
//   node tools/threatintel.js kev                                # KEV catalog stats
//
// Cache layout (reports/ is gitignored — generated data):
//   reports/cache/threatintel/nvd/<CVE>.json     { fetched_at, nvd: {...} }
//   reports/cache/threatintel/epss/<CVE>.json    { fetched_at, epss, percentile }
//   reports/cache/threatintel/kev-catalog.json   { fetched_at, kev: { <cveID>: entry } }
//
// Design rules (same ethics as the rest of the harness):
// - Read-only intel: lookups never touch a target, so no scope interaction; network calls go
//   to the three public feeds only.
// - Offline-safe: every fetch failure degrades to null / stale cache. A missing lookup is
//   "unknown", NEVER fabricated as "not vulnerable" or "0.0".
// - Deterministic core: record-finding.js reads ONLY the disk cache synchronously; going live
//   is an explicit `refresh` step (or --refresh flag), so findings never depend on network luck.
const fs = require('fs');
const path = require('path');
const { normCve } = require('./epss');

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';
const EPSS_API = 'https://api.first.org/data/v1/epss?cve=';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
// TTLs: EPSS changes daily; KEV feed updates daily-ish; NVD records rarely change once published.
const TTL_HOURS = { epss: 24, nvd: 24 * 7, kev: 24 };

function defaultCacheDir() {
  return process.env.TI_CACHE_DIR || path.join(__dirname, '..', 'reports', 'cache', 'threatintel');
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function writeAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.' + process.pid;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

function ageHours(iso, nowMs) {
  const t = Date.parse(iso || '');
  if (!Number.isFinite(t)) return Infinity;
  return Math.max(0, ((nowMs == null ? Date.now() : nowMs) - t) / 3600000);
}

function isFresh(entry, ttlHours, nowMs) {
  return !!entry && ageHours(entry.fetched_at, nowMs) <= ttlHours;
}

// ---- raw fetchers (ctx.fetch injectable for offline tests) ----

async function fetchNvd(cve, ctx) {
  ctx = ctx || {};
  const f = ctx.fetch || global.fetch;
  const id = normCve(cve);
  if (!id) return null;
  try {
    // Optional API key raises the NVD rate limit massively (env NVD_API_KEY).
    const headers = { 'User-Agent': 'stavros-harness-ti' };
    if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
    const r = await f(NVD_API + id, { headers, signal: ctx.signal });
    if (!r.ok) return null;
    const j = await r.json();
    const item = j && j.vulnerabilities && j.vulnerabilities[0] && j.vulnerabilities[0].cve;
    if (!item) return null;
    // Distill to owned leaf fields — keep the cache small and stable.
    const desc = (item.descriptions || []).find((d) => d.lang === 'en') || {};
    const cwes = [];
    for (const w of item.weaknesses || []) {
      for (const d of w.description || []) {
        if (/^CWE-\d+$/.test(d.value || '') && !cwes.includes(d.value)) cwes.push(d.value);
      }
    }
    let cvss = null, cvss_vector = null, cvss_source = null;
    const metricSets = (item.metrics && (item.metrics.cvssMetricV40 || item.metrics.cvssMetricV31 || item.metrics.cvssMetricV30 || item.metrics.cvssMetricV2)) || [];
    const m = Array.isArray(metricSets) ? metricSets[0] : null;
    const md = m && (m.cvssData || m);
    if (md && typeof md.baseScore === 'number') {
      cvss = md.baseScore;
      cvss_vector = md.vectorString || null;
      cvss_source = m.type === 'Secondary' ? 'nvd-secondary' : 'nvd-primary';
    }
    const refs = (item.references || []).map((x) => x.url).filter(Boolean).slice(0, 10);
    return {
      cve: id,
      published: item.published || null,
      last_modified: item.lastModified || null,
      description: desc.value || null,
      cwes,
      cvss, cvss_vector, cvss_source,
      refs,
      source: 'nvd-2.0',
    };
  } catch {
    return null;
  }
}

async function fetchEpss(cves, ctx) {
  ctx = ctx || {};
  const f = ctx.fetch || global.fetch;
  const ids = (Array.isArray(cves) ? cves : [cves]).map(normCve).filter(Boolean).slice(0, 100);
  if (!ids.length) return {};
  try {
    const r = await f(EPSS_API + ids.join(','), { headers: { 'User-Agent': 'stavros-harness-ti' }, signal: ctx.signal });
    if (!r.ok) return {};
    const j = await r.json();
    const out = {};
    for (const row of (j && j.data) || []) {
      const id = normCve(row.cve);
      if (id && row.epss != null) out[id] = { epss: Number(row.epss), percentile: row.percentile != null ? Number(row.percentile) : null, source: 'first-epss-api' };
    }
    return out;
  } catch {
    return {};
  }
}

async function fetchKev(ctx) {
  ctx = ctx || {};
  const f = ctx.fetch || global.fetch;
  try {
    const r = await f(KEV_URL, { headers: { 'User-Agent': 'stavros-harness-ti' }, signal: ctx.signal });
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || !Array.isArray(j.vulnerabilities)) return null;
    const index = {};
    for (const v of j.vulnerabilities) {
      if (v && v.cveID) index[v.cveID] = {
        date_added: v.dateAdded || null,
        due_date: v.dueDate || null,
        ransomware_use: v.knownRansomwareCampaignUse === 'Known',
        product: v.product || null,
        short_desc: (v.shortDescription || '').slice(0, 200),
      };
    }
    return { fetched_at_catalog: j.dateReleased || null, count: j.count || Object.keys(index).length, kev: index, source: 'cisa-kev' };
  } catch {
    return null;
  }
}

// ---- disk cache ----

function nvdCacheFile(cacheDir, cve) { return path.join(cacheDir, 'nvd', normCve(cve) + '.json'); }
function epssCacheFile(cacheDir, cve) { return path.join(cacheDir, 'epss', normCve(cve) + '.json'); }
function kevCacheFile(cacheDir) { return path.join(cacheDir, 'kev-catalog.json'); }

function cachedNvd(cve, ctx) {
  ctx = ctx || {};
  const dir = ctx.cacheDir || defaultCacheDir();
  const e = readJson(nvdCacheFile(dir, cve));
  return e && e.nvd ? e.nvd : null; // stale entries still returned; lookupCached flags them
}

function cachedEpss(cve, ctx) {
  ctx = ctx || {};
  const dir = ctx.cacheDir || defaultCacheDir();
  const e = readJson(epssCacheFile(dir, cve));
  if (!e) return null;
  const fresh = isFresh(e, TTL_HOURS.epss, ctx.now);
  return { epss: e.epss, percentile: e.percentile, source: e.source || 'first-epss-api', stale: !fresh };
}

function cachedKevIndex(ctx) {
  ctx = ctx || {};
  const dir = ctx.cacheDir || defaultCacheDir();
  const e = readJson(kevCacheFile(dir));
  if (!e || !e.kev) return null;
  return e;
}

// One KEV catalog per refresh batch: memoized as a pending promise on ctx.
function kevCatalogOnce(ctx) {
  if (!ctx._kevPromise) ctx._kevPromise = fetchKev(ctx).then((cat) => {
    if (cat) writeAtomic(kevCacheFile(ctx.cacheDir || defaultCacheDir()), JSON.stringify({ fetched_at: new Date().toISOString(), ...cat }));
    return cat;
  });
  return ctx._kevPromise;
}

// Refresh one CVE into the cache (NVD + EPSS + KEV membership). Returns what it got;
// individual failures degrade to null entries (offline-safe, old cache left untouched).
async function refreshCve(cve, ctx) {
  ctx = ctx || {};
  const dir = ctx.cacheDir || defaultCacheDir();
  const id = normCve(cve);
  if (!id) return { cve: String(cve), error: 'invalid CVE id' };
  const out = { cve: id, nvd: null, epss: null, kev: null };
  // NVD
  const nvd = await fetchNvd(id, ctx);
  if (nvd) {
    writeAtomic(nvdCacheFile(dir, id), JSON.stringify({ fetched_at: new Date().toISOString(), nvd }));
    out.nvd = nvd;
  }
  // EPSS
  const eps = await fetchEpss([id], ctx);
  const hit = eps[id];
  if (hit) {
    writeAtomic(epssCacheFile(dir, id), JSON.stringify({ fetched_at: new Date().toISOString(), ...hit }));
    out.epss = hit;
  }
  // KEV membership (catalog fetched at most once per batch)
  const cat = await kevCatalogOnce(ctx);
  if (cat && cat.kev[id]) out.kev = cat.kev[id];
  return out;
}

// Batch refresh: one KEV fetch for all CVEs, NVD/EPSS per CVE with optional pacing.
async function refreshAll(cves, ctx) {
  ctx = ctx || {};
  const ids = (Array.isArray(cves) ? cves : [cves]).map(normCve).filter(Boolean);
  const results = [];
  for (const id of ids) {
    results.push(await refreshCve(id, ctx));
    if (ctx.delayMs) await new Promise((res) => setTimeout(res, ctx.delayMs));
  }
  return results;
}

// Refresh ONLY the KEV catalog into the disk cache (daily jobs run this even on days with
// no new findings, so kev:true/false stays meaningful).
async function refreshKevCatalog(ctx) {
  ctx = ctx || {};
  const cat = await fetchKev(ctx);
  if (cat) {
    writeAtomic(kevCacheFile(ctx.cacheDir || defaultCacheDir()), JSON.stringify({ fetched_at: new Date().toISOString(), ...cat }));
    return { ok: true, entries: Object.keys(cat.kev).length };
  }
  return { ok: false, error: 'KEV catalog fetch failed (offline?)' };
}

// Merged lookup, CACHE-ONLY (synchronous, deterministic — safe inside record-finding).
// Returns null when nothing is cached. Stale entries are included but flagged.
function lookupCached(cve, ctx) {
  ctx = ctx || {};
  const id = normCve(cve);
  if (!id) return null;
  const nvd = cachedNvd(id, ctx);
  const epssEntry = cachedEpss(id, ctx);
  const kevIdx = cachedKevIndex(ctx);
  const kevHit = kevIdx && kevIdx.kev[id];
  if (!nvd && !epssEntry && !kevHit) return null;
  const intel = { cve: id };
  if (epssEntry) intel.epss = epssEntry.epss, intel.percentile = epssEntry.percentile, intel.epss_source = epssEntry.source;
  if (kevHit) {
    intel.kev = true;
    intel.kev_date_added = kevHit.date_added;
    intel.kev_ransomware = kevHit.ransomware_use;
  } else if (kevIdx) {
    intel.kev = false; // catalog present, CVE not listed — meaningful negative
  }
  if (nvd) {
    if (nvd.cwes && nvd.cwes.length) intel.cwes = nvd.cwes;
    if (nvd.description) intel.description = nvd.description;
    if (nvd.cvss != null) intel.cvss = nvd.cvss;
    if (nvd.cvss_vector) intel.cvss_vector = nvd.cvss_vector;
    if (nvd.refs && nvd.refs.length) intel.refs = nvd.refs.slice(0, 5);
    const fetchedAt = cachedNvdFetchedAt(id, ctx);
    if (!isFresh({ fetched_at: fetchedAt }, TTL_HOURS.nvd, ctx.now)) intel.stale_nvd = true;
  }
  return Object.keys(intel).length > 1 ? intel : null;
}

function cachedNvdFetchedAt(cve, ctx) {
  const e = readJson(nvdCacheFile(ctx.cacheDir || defaultCacheDir(), cve));
  return e ? e.fetched_at : null;
}

// ---- CLI ----

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const doRefresh = argv.includes('--refresh');
  const cves = argv.slice(1).filter((a) => !a.startsWith('--')).map(normCve).filter(Boolean);
  if (cmd === 'refresh' && cves.length) {
    const res = await refreshAll(cves, {});
    console.log(JSON.stringify({ refreshed: res.length, results: res }, null, 2));
    process.exit(0);
  }
  if (cmd === 'lookup') {
    const out = [];
    for (const c of cves) {
      if (doRefresh) await refreshCve(c, {});
      out.push(lookupCached(c, {}) || { cve: normCve(c) || c, unknown: true });
    }
    console.log(JSON.stringify(out.length === 1 ? out[0] : out, null, 2));
    process.exit(0);
  }
  if (cmd === 'kev') {
    if (doRefresh || !cachedKevIndex({})) {
      const cat = await fetchKev({});
      if (cat) writeAtomic(kevCacheFile(defaultCacheDir()), JSON.stringify({ fetched_at: new Date().toISOString(), ...cat }));
    }
    const idx = cachedKevIndex({});
    if (!idx) { console.error(JSON.stringify({ error: 'KEV catalog unavailable (offline?)' })); process.exit(1); }
    console.log(JSON.stringify({ catalog_fetched_at: idx.fetched_at, entries: Object.keys(idx.kev).length, sample_cves: Object.keys(idx.kev).slice(0, 5) }, null, 2));
    process.exit(0);
  }
  console.error('usage: node tools/threatintel.js refresh <CVE...> | lookup <CVE...> [--refresh] | kev [--refresh]');
  process.exit(2);
}
if (require.main === module) main();

module.exports = {
  NVD_API, EPSS_API, KEV_URL, TTL_HOURS, defaultCacheDir,
  fetchNvd, fetchEpss, fetchKev,
  refreshCve, refreshAll, refreshKevCatalog, lookupCached,
  cachedNvd, cachedEpss, cachedKevIndex,
};
