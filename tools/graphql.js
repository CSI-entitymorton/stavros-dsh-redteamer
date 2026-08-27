#!/usr/bin/env node
// GraphQL tester (zero-dep, scope-guarded). Makes introspection-driven enumeration and
// BOLA testing deterministic:
//   node tools/graphql.js introspect <url> [--header "K: V"] [--force]
//       -> POSTs the full __schema introspection query, saves reports/tmp/<host>-schema.json,
//          prints summary (type count, query/mutation/subscription field lists)
//   node tools/graphql.js types <url> [--header "K: V"]
//       -> list type names (reuses the saved schema if present)
//   node tools/graphql.js fields <url> <TypeName> [--header "K: V"]
//       -> fields + args of one type (reuses saved schema if present)
//   node tools/graphql.js query <url> '<gql>' [--header "K: V"] [--show]
//       -> execute an arbitrary query/mutation; prints the JSON result
// introspection itself enabled is a finding (schema disclosure) -> record it.
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { loadScope, inScope } = require('./scope-guard');
const { wait } = require('./pace');

const INTROSPECTION_QUERY = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }`;

function schemaPath(url) {
  const host = new URL(url).hostname.replace(/[^a-z0-9.-]/gi, '_');
  return path.join(__dirname, '..', 'reports', 'tmp', host + '-schema.json');
}

function request(url, body, headers, timeoutMs) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https:') ? https : http;
    const t0 = Date.now();
    let done = false;
    const fin = (r) => { if (!done) { done = true; resolve(r); } };
    const req = lib.request(url, {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json', 'User-Agent': 'Stavros/0.1' }, headers),
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      let len = 0;
      res.on('data', (d) => { len += d.length; chunks.push(d); });
      res.on('end', () => fin({ status: res.statusCode, bytes: len, body: Buffer.concat(chunks).toString('utf8'), ms: Date.now() - t0 }));
    });
    req.on('timeout', () => { req.destroy(); fin({ timeout: true, ms: Date.now() - t0 }); });
    req.on('error', (e) => fin({ error: e.message, ms: Date.now() - t0 }));
    req.write(JSON.stringify(body));
    req.end();
  });
}

function parseHeaders(argv) {
  const headers = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--header' && argv[i + 1]) {
      const h = argv[i + 1];
      const j = h.indexOf(':');
      if (j > 0) headers[h.slice(0, j).trim()] = h.slice(j + 1).trim();
    }
  }
  return headers;
}

function loadSaved(url) {
  try {
    return JSON.parse(fs.readFileSync(schemaPath(url), 'utf8'));
  } catch {
    return null;
  }
}

function summarize(schema) {
  const t = schema.data.__schema;
  const q = t.queryType ? t.queryType.name : null;
  const m = t.mutationType ? t.mutationType.name : null;
  const s = t.subscriptionType ? t.subscriptionType.name : null;
  const typeByName = {};
  for (const ty of t.types) typeByName[ty.name] = ty;
  const fieldsOf = (name) => (name && typeByName[name] && typeByName[name].fields || []).map((f) => f.name);
  return {
    query_type: q,
    mutation_type: m,
    subscription_type: s,
    type_count: t.types.length,
    queries: fieldsOf(q),
    mutations: fieldsOf(m),
    subscriptions: fieldsOf(s),
  };
}

async function main() {
  const argv = process.argv.slice(2);
  const [cmd, url, arg2] = argv;
  const headers = parseHeaders(argv);
  const timeout = +argv[argv.indexOf('--timeout') + 1] || 15000;
  const force = argv.includes('--force');

  if (!cmd || !url) {
    console.error('usage: node tools/graphql.js introspect|types|fields|query <url> [<TypeName>|<gql>] [--header "K: V"]');
    process.exit(2);
  }
  const scope = loadScope();
  const g = inScope(url, scope);
  if (!g.ok) {
    console.error(JSON.stringify({ blocked: url, reason: g.reason }));
    process.exit(1);
  }
  const rps = Math.max(0.1, scope.max_requests_per_second || 2);

  if (cmd === 'introspect') {
    wait(rps);
    const r = await request(url, { query: INTROSPECTION_QUERY }, headers, timeout);
    if (r.error || r.timeout) {
      console.error(JSON.stringify({ error: r.error || 'timeout', status: r.status }));
      process.exit(1);
    }
    let json;
    try {
      json = JSON.parse(r.body);
    } catch {
      console.error(JSON.stringify({ error: 'non-JSON response (status ' + r.status + ') — introspection likely disabled', body: r.body.slice(0, 300) }));
      process.exit(1);
    }
    if (json.errors && !json.data) {
      console.error(JSON.stringify({ error: 'introspection rejected', errors: json.errors.slice(0, 5) }));
      process.exit(1);
    }
    try {
      fs.mkdirSync(path.dirname(schemaPath(url)), { recursive: true });
      fs.writeFileSync(schemaPath(url), JSON.stringify(json, null, 2));
    } catch {}
    console.log(JSON.stringify({ source: url, status: r.status, enabled: true, ...summarize(json) }, null, 2));
    return;
  }

  if (cmd === 'types' || cmd === 'fields') {
    let schema = loadSaved(url);
    if (!schema || force) {
      wait(rps);
      const r = await request(url, { query: INTROSPECTION_QUERY }, headers, timeout);
      if (r.body) {
        try {
          schema = JSON.parse(r.body);
        } catch {}
      }
    }
    if (!schema || !schema.data || !schema.data.__schema) {
      console.error(JSON.stringify({ error: 'no schema available (introspection disabled or no saved schema)' }));
      process.exit(1);
    }
    const types = schema.data.__schema.types.filter((t) => !t.name.startsWith('__'));
    if (cmd === 'types') {
      console.log(JSON.stringify(types.map((t) => ({ name: t.name, kind: t.kind })), null, 2));
      return;
    }
    const ty = types.find((t) => t.name === arg2);
    if (!ty) {
      console.error(JSON.stringify({ error: 'type not found: ' + arg2, available: types.map((t) => t.name).slice(0, 50) }));
      process.exit(1);
    }
    console.log(JSON.stringify({
      name: ty.name, kind: ty.kind,
      fields: (ty.fields || []).map((f) => ({
        name: f.name, args: (f.args || []).map((a) => a.name + ':' + a.type.name + (a.defaultValue != null ? '=' + a.defaultValue : '')),
        type: f.type.name,
      })),
      input_fields: (ty.inputFields || []).map((f) => f.name),
      enum_values: (ty.enumValues || []).map((v) => v.name),
    }, null, 2));
    return;
  }

  if (cmd === 'query') {
    const gql = arg2;
    if (!gql) {
      console.error('usage: node tools/graphql.js query <url> \'<gql>\' [--header "K: V"]');
      process.exit(2);
    }
    wait(rps);
    const r = await request(url, { query: gql }, headers, timeout);
    const out = { status: r.status, ms: r.ms };
    if (r.error) out.error = r.error;
    else if (r.timeout) out.timeout = true;
    else {
      try {
        out.result = JSON.parse(r.body);
      } catch {
        out.body = r.body.slice(0, 4096);
      }
    }
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  console.error('unknown command: ' + cmd);
  process.exit(2);
}

module.exports = { INTROSPECTION_QUERY, summarize, schemaPath };
if (require.main === module) main();
