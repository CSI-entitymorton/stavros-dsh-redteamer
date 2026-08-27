// runner.ts — hydration degli asset nel workspace + esecuzione dei tool scope-gated.
//
// Design: il plugin "idrata" il workspace di sessione rendendolo una root di engagement
// Stavros (tools/, knowledge.md, refs/, skills/, subagents/ + scope.example.json se manca
// scope.json). L'agente e i wrapper usano QUEL workspace: zero path assoluti, tutto ciò che
// esiste già in StavrosRedTeamer (persona, subagent, metodologia, tool) funziona invariato.
//
// Ogni tool viene eseguito come `node <workspace>/tools/<x>.js ...` con cwd = workspace:
// i guard (scope-guard.js, run.js, repeater.js, ...) trovano scope.json al posto giusto
// (tools/ sta sotto il workspace) e i report finiscono in <workspace>/reports/.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/** Radice del pacchetto (stessa profondità da src/ in dev e da lib/ in produzione). */
export function packageRoot(): string {
  // '..' da src/runner.ts o lib/runner.js → radice del pacchetto (URL parte dalla dir del file)
  return fileURLToPath(new URL('..', import.meta.url))
}

export function packageVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot(), 'package.json'), 'utf8'))
    return String(pkg.version ?? '0.0.0')
  } catch {
    return '0.0.0'
  }
}

/** Workspace di sessione: override con STAVROS_WORKSPACE, default cwd del processo dsh. */
export function workspaceDir(): string {
  return process.env.STAVROS_WORKSPACE ?? process.cwd()
}

/** Asset che il plugin idrata nel workspace (merging, mai sovrascrive dati esistenti). */
const HYDRATE_ITEMS = ['tools', 'knowledge.md', 'refs', 'skills', 'subagents'] as const

function copyMissing(src: string, dst: string): void {
  const st = fs.statSync(src)
  if (st.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true })
    for (const entry of fs.readdirSync(src)) {
      copyMissing(path.join(src, entry), path.join(dst, entry))
    }
  } else if (!fs.existsSync(dst)) {
    fs.copyFileSync(src, dst)
  }
}

/**
 * Idrata gli asset del pacchetto nel workspace (una sola volta per versione, marker
 * `.stavros-version`). Non tocca mai file esistenti: merge add-only. Se manca scope.json,
 * crea scope.example.json → scope vuoto = fail-closed finché l'operatore non lo compila.
 */
export function hydrate(force = false): string {
  const ws = workspaceDir()
  const stamp = path.join(ws, '.stavros-version')
  try {
    if (!force && fs.readFileSync(stamp, 'utf8').trim() === packageVersion()) return ws
  } catch {
    /* primo boot */
  }
  const root = packageRoot()
  for (const item of HYDRATE_ITEMS) {
    const src = path.join(root, item)
    if (!fs.existsSync(src)) continue
    copyMissing(src, path.join(ws, item))
  }
  const scope = path.join(ws, 'scope.json')
  if (!fs.existsSync(scope)) {
    const example = path.join(root, 'templates', 'scope.example.json')
    if (fs.existsSync(example)) fs.copyFileSync(example, scope)
  }
  fs.writeFileSync(stamp, packageVersion())
  return ws
}

export interface RunResult {
  ok: boolean
  exit: number | null
  stdout: string
  stderr: string
}

/** Esegue `node <workspace>/tools/<tool> <args...>` con cwd = workspace. */
export function runTool(tool: string, args: string[], opts: { timeoutMs?: number } = {}): RunResult {
  const ws = workspaceDir()
  const script = path.join(ws, 'tools', tool)
  const res = spawnSync(process.execPath, [script, ...args], {
    cwd: ws,
    env: process.env,
    encoding: 'utf8',
    timeout: opts.timeoutMs ?? 120_000,
    maxBuffer: 64 * 1024 * 1024,
  })
  if (res.error) return { ok: false, exit: null, stdout: '', stderr: String(res.error) }
  return { ok: res.status === 0, exit: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' }
}
