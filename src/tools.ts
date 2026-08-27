// tools.ts — i tool model-facing del plugin: wrapper defineTool attorno ai tool node
// scope-gated di tools/ (l'unica fonte di verità runtime è il workspace idratato).
//
// Pattern: spec table-driven (script + description + parameters + buildArgs). Aggiungere
// un tool = aggiungere una riga + lo spec dei parametri. I guard HARD vivono nei tool
// (scope-guard/repeater/run/oob/... leggono scope.json in codice): il wrapper non può
// bypassarli e non espone flag di disattivazione.
import type { Context } from '@deepseek-ai/cordis'
import {
  defineTool,
  type ParameterPropertySpec,
  type ParameterSchemaSpec,
  type ValueSchemaSpec,
} from '@deepseek-ai/dsh-tools'

export interface ToolSpec {
  /** nome del tool model-facing (prefisso stavros_) */
  name: string
  /** nome file in tools/ */
  script: string
  description: string
  /** ParameterSchemaSpec: descrive i parametri al modello */
  parameters: ParameterSchemaSpec
  /** costruisce l'argv per `node tools/<script>` */
  buildArgs(args: Record<string, unknown>): string[]
  /** timeout di esecuzione in ms (opzione nativa di defineTool) */
  timeoutMs?: number
}

const str = (description: string, required = false): ParameterPropertySpec => ({
  type: 'string',
  description,
  ...(required ? { required: true as const } : {}),
})

const bool = (description: string): ParameterPropertySpec => ({
  type: 'boolean',
  description,
})

const strArray = (description: string): ParameterPropertySpec => ({
  type: 'array',
  items: { type: 'string' },
  description,
})

export const TOOL_SPECS: ToolSpec[] = [
  {
    name: 'stavros_scope_check',
    script: 'scope-guard.js',
    description:
      'Scope guard: check if a URL/host is authorized in scope.json (exit 0 = allowed, non-zero = blocked). Run this BEFORE any tool that touches a target. Fail-closed: empty scope.json blocks everything.',
    parameters: {
      target: str('URL or host to check, e.g. https://target.com or 10.0.0.5', true),
    },
    buildArgs: (a) => ['check', String(a.target)],
  },
  {
    name: 'stavros_repeater',
    script: 'repeater.js',
    description:
      'Precise HTTP tampering with hard scope guard + global pacing: --url <u> [--vary p=v1,v2] [--as <identity>] [--diff] [--follow] [--show-body]. Use --vary for IDOR/BOLA tests, --as loads a bearer from auth.json, literal FUZZ in path/body is substituted.',
    parameters: {
      url: str('Target URL, e.g. https://target.com/api/items/FUZZ', true),
      vary: str('Query param to vary, e.g. id=1,2,3'),
      as: str('Identity from auth.json for authed tests'),
      showBody: bool('Capture first 2KB of each response body (confirm findings)'),
      diff: bool('Add body_similarity vs baseline in --vary mode'),
      follow: bool('Follow redirects (scope re-checked each hop)'),
    },
    buildArgs: (a) => {
      const out = ['--url', String(a.url)]
      if (a.vary) out.push('--vary', String(a.vary))
      if (a.as) out.push('--as', String(a.as))
      if (a.showBody) out.push('--show-body')
      if (a.diff) out.push('--diff')
      if (a.follow) out.push('--follow')
      return out
    },
  },
  {
    name: 'stavros_run',
    script: 'run.js',
    description:
      'Scope-safe binary runner: run any third-party scanner/tool via the gate (refuses out-of-scope hosts, audits every invocation, respects pacing). e.g. binary=nuclei args=["-u","https://host","-tags","injection"]. NEVER run scanner binaries directly.',
    parameters: {
      binary: str('Binary to run, e.g. nuclei, nmap, sqlmap, ffuf, httpx', true),
      args: strArray('CLI arguments for the binary'),
    },
    buildArgs: (a) => [String(a.binary), ...(Array.isArray(a.args) ? a.args.map(String) : [])],
  },
  {
    name: 'stavros_analyze_bundle',
    script: 'analyze-bundle.js',
    description:
      'Bundle miner: extract JWTs (decoded), Supabase projects, secrets and endpoints from a JS/HTML bundle (follows sourceMappingURL into .map files). Run on every JS/HTML bundle FIRST.',
    parameters: {
      target: str('URL or local file of the bundle', true),
    },
    buildArgs: (a) => [String(a.target)],
  },
  {
    name: 'stavros_record_finding',
    script: 'record-finding.js',
    description:
      'Record a finding into reports/findings.jsonl (deduped, evidence auto-redacted). JSON payload with severity, title, host, endpoint, poc, status, verify_level, cvss, cvss_vector, cwe, cve, remediation. Do this for EVERY confirmed finding.',
    parameters: {
      json: str('JSON payload for the finding (single JSON object)', true),
    },
    buildArgs: (a) => [String(a.json)],
  },
  {
    name: 'stavros_verify_finding',
    script: 'verify-finding.js',
    description:
      'Re-fire a finding verify block live against the target (oracle): pass a JSON with the verify block; status becomes verified only on N/N success.',
    parameters: {
      json: str('JSON payload containing the verify block', true),
    },
    buildArgs: (a) => ['one', String(a.json)],
  },
  {
    name: 'stavros_jwt',
    script: 'jwt.js',
    description:
      'JWT toolkit: decode <token>, verify <token> --key <s>, forge <token> --alg none|HS256|RS256 --key <s> [--set role=admin], attack <url> --token <jwt> --keys <f|k1,k2> [--set role=admin] [--show-body].',
    parameters: {
      args: strArray('jwt.js CLI arguments, e.g. ["decode","<token>"] or ["attack","<url>","--token","<jwt>"]'),
    },
    buildArgs: (a) => (Array.isArray(a.args) ? a.args.map(String) : []),
  },
  {
    name: 'stavros_oob',
    script: 'oob.js',
    description:
      'Out-of-band listener for blind SSRF/XXE: listen, marker, hits [--tail N] [--marker <t>], stop. Inject the marker URL into URL-fetching params; hits proves the fetch.',
    parameters: {
      action: str('listen | marker | hits | stop', true),
      args: strArray('Extra oob.js args, e.g. ["--tail","5"] or ["--marker","<token>"]'),
    },
    buildArgs: (a) => [String(a.action), ...(Array.isArray(a.args) ? a.args.map(String) : [])],
  },
  {
    name: 'stavros_map',
    script: 'map.js',
    description:
      'Structured endpoint map: add \'<json>\' records an endpoint + candidate params per vuln class; candidates <host> returns the deterministic handoff for testers.',
    parameters: {
      action: str('add | candidates', true),
      args: strArray('map.js args, e.g. ["add","{...json...}"] or ["candidates","<host>"]'),
    },
    buildArgs: (a) => [String(a.action), ...(Array.isArray(a.args) ? a.args.map(String) : [])],
  },
  {
    name: 'stavros_gate',
    script: 'gate.js',
    description:
      'Stage gate: status <host> shows which phase gates are passed (recon→map→test→authed→chains→report); pass <gate> <host> once the structural criteria hold. The report gate requires findings recorded, one verified, none pending, coverage matrix complete.',
    parameters: {
      action: str('status | pass', true),
      host: str('Target host', true),
      phase: str('Phase name for pass, e.g. recon, map, test, report'),
    },
    buildArgs: (a) => (a.action === 'pass' ? ['pass', String(a.phase), String(a.host)] : ['status', String(a.host)]),
  },
  {
    name: 'stavros_coverage',
    script: 'coverage.js',
    description:
      'Coverage matrix per vuln class for a host: <host> [--write] records the per-class coverage (coverage-matrix.md); the report gate needs a complete matrix.',
    parameters: {
      host: str('Target host', true),
      write: bool('Persist the matrix (--write)'),
    },
    buildArgs: (a) => [String(a.host), ...(a.write ? ['--write'] : [])],
  },
  {
    name: 'stavros_gen_poc',
    script: 'gen-poc.js',
    description:
      'Generate a standalone parameterized Python reproducer for a verified finding into reports/exp/<finding-id>.py (-u/--target required, read-only by default, exit 0 = reproduced). Reference it in the report.',
    parameters: {
      id: str('Finding id, or --latest', true),
    },
    buildArgs: (a) => [String(a.id)],
  },
]

export function registerTools(ctx: Context): void {
  for (const spec of TOOL_SPECS) {
    ctx.tools.register(
      defineTool({
        name: spec.name,
        description: spec.description,
        parameters: spec.parameters,
        timeoutMs: spec.timeoutMs,
        output: {
          schema: { type: 'string' } satisfies ValueSchemaSpec,
          render: (_args, value) => [{ type: 'text', text: value }],
        },
        async execute(args) {
          const { runTool } = await import('./runner.js')
          const res = runTool(spec.script, spec.buildArgs(args as unknown as Record<string, unknown>))
          if (!res.ok) {
            const detail = (res.stderr || res.stdout || '').trim()
            throw new Error(`exit ${res.exit ?? 'null'}${detail ? `: ${detail}` : ''}`)
          }
          return res.stdout
        },
      }),
    )
  }
}
