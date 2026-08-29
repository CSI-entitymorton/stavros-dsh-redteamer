// index.ts — stavros-dsh-redteamer bundle plugin.
//
// On apply:
//   1. hydrate() copies the packaged assets (tools/, knowledge.md, refs/, skills/,
//      subagents/) into the session workspace — merge-only, never clobbers user data,
//      and seeds an EMPTY scope.json (fail-closed) when none exists.
//   2. registers the stavros_* model-facing tools (thin wrappers over the gated tools).
//
// The persona/subagents/skills are contributed by cordis.patch.yml (see file header).
import type { Context } from '@deepseek-ai/cordis'
import { hydrate, packageVersion, workspaceDir } from './runner.js'
import { registerTools } from './tools.js'

export const name = 'stavros-dsh-redteamer'

/** dipende dai servizi tools (registrazione tool) */
export const inject = ['tools']

export function apply(ctx: Context): void {
  const ws = hydrate()
  console.log(`[stavros-dsh-redteamer] v${packageVersion()} hydrated assets into ${ws}`)
  registerTools(ctx)
  void ctx
}
