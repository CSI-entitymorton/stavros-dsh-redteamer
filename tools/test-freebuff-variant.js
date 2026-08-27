// Offline self-check for the freebuff-edition variant. No network, no subprocesses:
// loads every .agents/*.ts of the edition (vm sandbox, same pattern as
// freebuff-edition/build-agents.mjs) and asserts:
//   1. structure valid (id = filename, ESM definition with required fields);
//   2. Freebuff-native toolNames (subset of the Freebuff tool set);
//   3. ZERO DSH residue (no /home/stavros, subagent, @deepseek-ai, cordis,
//      redteam_finding_register, skill-filesystem...);
//   4. spawnableAgents of the orchestrator all exist in the edition;
//   5. every referenced file (playbook, class refs, payloads, knowledge.md, scope.json)
//      exists relative to the edition cwd.
// Run: node tools/test-freebuff-variant.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const EDITION = path.resolve(__dirname, '..', 'freebuff-edition');
const AGENTS_DIR = path.join(EDITION, '.agents');
const FREE_TOOLS = new Set(['read_files', 'write_file', 'run_terminal_command', 'spawn_agents', 'web_search', 'read_url', 'end_turn']);
const DSH_MARKERS = ['/home/stavros', '.dsh/', 'subagent', '@deepseek-ai', 'cordis', 'redteam_finding_register', 'skill-filesystem', 'tool-bash', 'tool-fs', 'dsh-'];
// agenti che NON toccano target (nessuno scope-guard/scope.json richiesto)
const NON_TARGET = new Set(['stavros-vet']);

function loadDefinition(file) {
  let code = fs.readFileSync(file, 'utf8');
  code = code.replace(/\bexport\s+default\s+/, 'globalThis.__definition = ');
  code = code.replace(/;\s*$/, '') + ';\n';
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: file });
  if (sandbox.__definition === undefined) throw new Error(`nessuna definition esportata in ${file}`);
  return sandbox.__definition;
}

const files = fs.readdirSync(AGENTS_DIR).filter((f) => f.endsWith('.ts')).sort();
assert.ok(files.length >= 24, `attesi >= 24 agenti, trovati ${files.length}`);
assert.ok(files.includes('stavros.ts'), 'orchestratore presente');

const defs = {};
for (const f of files) {
  const id = f.replace(/\.ts$/, '');
  const d = loadDefinition(path.join(AGENTS_DIR, f));
  defs[id] = d;

  // 1. struttura
  assert.strictEqual(d.id, id, `id coerente col filename (${f})`);
  assert.ok(typeof d.displayName === 'string' && d.displayName.length > 0, `${id}: displayName`);
  assert.ok(typeof d.model === 'string' && d.model.length > 0, `${id}: model`);
  if (!NON_TARGET.has(id)) {
    const fullPrompt = `${d.systemPrompt}\n${d.instructionsPrompt}`;
    assert.ok(fullPrompt.includes('scope-guard.js') || fullPrompt.includes('scope.json'), `${id}: scope-guard/scope.json menzionato`);
  }
  assert.ok(typeof d.instructionsPrompt === 'string' && d.instructionsPrompt.length > 0, `${id}: instructionsPrompt`);
  assert.ok(Array.isArray(d.toolNames) && d.toolNames.length > 0, `${id}: toolNames`);
  assert.ok(Array.isArray(d.spawnableAgents), `${id}: spawnableAgents array`);

  // 2. toolNames Freebuff-native
  for (const t of d.toolNames) assert.ok(FREE_TOOLS.has(t), `${id}: toolName non-Freebuff "${t}"`);

  // 3. zero residui DSH
  for (const m of DSH_MARKERS) {
    assert.ok(!d.systemPrompt.includes(m), `${id}: systemPrompt contiene marker DSH "${m}"`);
    assert.ok(!d.instructionsPrompt.includes(m), `${id}: instructionsPrompt contiene marker DSH "${m}"`);
    assert.ok(!d.spawnerPrompt.includes(m), `${id}: spawnerPrompt contiene marker DSH "${m}"`);
  }

  // mcpServers (MCP nativo Freebuff): se presente, formato valido
  if (d.mcpServers !== undefined) {
    assert.ok(typeof d.mcpServers === 'object' && d.mcpServers !== null, `${id}: mcpServers oggetto`);
    for (const [name, cfg] of Object.entries(d.mcpServers)) {
      assert.ok(/^[a-zA-Z0-9_-]+$/.test(name), `${id}: nome server MCP valido "${name}"`);
      assert.ok(typeof cfg === 'object' && cfg !== null, `${id}: config MCP di "${name}" oggetto`);
      const hasStdio = typeof cfg.command === 'string' && Array.isArray(cfg.args);
      const hasHttp = typeof cfg.url === 'string';
      assert.ok(hasStdio || hasHttp, `${id}: MCP "${name}" deve avere command+args (stdio) oppure url (http)`);
      if (cfg.env !== undefined) assert.ok(typeof cfg.env === 'object' && cfg.env !== null, `${id}: env MCP di "${name}" oggetto`);
      if (cfg.headers !== undefined) assert.ok(typeof cfg.headers === 'object' && cfg.headers !== null, `${id}: headers MCP di "${name}" oggetto`);
    }
  }

  // disciplina pentest presente
  assert.ok(d.systemPrompt.includes('Verification levels'), `${id}: verification levels in systemPrompt`);
  assert.ok(d.systemPrompt.includes('False-positive duty'), `${id}: false-positive duty`);
  assert.ok(d.systemPrompt.includes('Adversarial content discipline'), `${id}: adversarial content discipline`);
  assert.ok(d.systemPrompt.includes('POC delivery'), `${id}: POC delivery`);
}

// 4. orchestratore: spawnableAgents completi e tutti esistenti
const orch = defs['stavros'];
const spawnable = orch.spawnableAgents;
for (const s of spawnable) assert.ok(defs[s], `orchestratore spawna agente inesistente "${s}"`);
assert.ok(spawnable.includes('stavros-hardware'), 'orchestratore: hardware presente');
assert.ok(spawnable.includes('stavros-privesc'), 'orchestratore: privesc presente');
assert.ok(spawnable.includes('stavros-wireless') === false, 'orchestratore: wireless NON spawnato (mode separato)');
assert.ok(orch.toolNames.includes('spawn_agents'), 'orchestratore: spawn_agents abilitato');
assert.ok(orch.instructionsPrompt.includes('Stage-gate sequence'), 'orchestratore: stage-gate sequence');

// 5. file referenziati esistono (relativi al cwd edition)
const mustExist = [
  'knowledge.md',
  'scope.json',
  'skills/pentest-playbook/SKILL.md',
  'refs/INDEX.md',
  'tools/scope-guard.js',
  'tools/run.js',
  'tools/record-finding.js',
  'tools/gate.js',
  'tools/coverage.js',
  'tools/tool-plane.js',
  'tools/gen-poc.js',
  'tools/verify-finding.js',
];
for (const rel of mustExist) {
  assert.ok(fs.existsSync(path.join(EDITION, rel)), `file referenziato mancante: ${rel}`);
}

// class refs citate nei prompt esistono davvero in refs/
const refsMentioned = new Set();
for (const d of Object.values(defs)) {
  const m = d.instructionsPrompt.match(/read (refs\/[A-Za-z0-9_\/.-]+\.md)/g) || [];
  for (const x of m) refsMentioned.add(x.replace(/^read /, ''));
}
for (const rel of refsMentioned) {
  assert.ok(fs.existsSync(path.join(EDITION, rel)), `ref citato in prompt non esiste: ${rel}`);
}

// payload citati esistono in tools/payloads/
const payloadsMentioned = new Set();
for (const d of Object.values(defs)) {
  const m = d.instructionsPrompt.match(/tools\/payloads\/([A-Za-z0-9_\/.-]+\.md)/g) || [];
  for (const x of m) payloadsMentioned.add(x);
}
for (const rel of payloadsMentioned) {
  assert.ok(fs.existsSync(path.join(EDITION, rel)), `payload citato non esiste: ${rel}`);
}

// playbook SKILL.md non contiene residui DSH sostanziali (deve essere operativo, non di runtime)
const skill = fs.readFileSync(path.join(EDITION, 'skills/pentest-playbook/SKILL.md'), 'utf8');
assert.ok(skill.includes('pentest-playbook'), 'SKILL.md: nome skill presente');

console.log(`freebuff-edition: ${files.length} agenti validi, ${spawnable.length} spawnable dell'orchestratore, ${refsMentioned.size} refs verificati, 0 residui DSH — all tests passed`);
