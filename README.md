# dsh-stavros — Stavros RedTeam for DeepSeek Harness

> ⚠️ **AUTHORIZED USE ONLY.** This plugin is a red-team / offensive-security harness. Use it
> **only** against systems you own or have **written authorization** to test. Authorization is
> enforced by code, not by good intentions: every guarded tool reads `scope.json`, and an empty
> `scope.json` **blocks everything** (fail-closed). You are responsible for the targets you put
> in scope.

Stavros RedTeam as a native DSH (DeepSeek Harness) plugin: the full authorized red-team persona
(24 specialist subagents), the pentest methodology, and the 78 zero-dependency scope-guarded
tools — installable with `dsh plugin add`, no manual preset wiring.

- **Cervello**: orchestrator persona + 24 specialists (`stavros-ad`, `stavros-sqli`,
  `stavros-authn`, `stavros-authz`, `stavros-recon`, …), `knowledge.md` methodology, 106-file
  `refs/` knowledge base, `pentest-playbook` skill.
- **Muscoli**: the `tools/` suite — `scope-guard.js`, `repeater.js`, `run.js`,
  `analyze-bundle.js`, `record-finding.js`, `oob.js`, `jwt.js`, `cors.js`, `csp.js`, `map.js`,
  `gate.js`, `coverage.js`, `gen-poc.js` and more — exposed both as `stavros_*` model-facing
  tools and as gated CLI commands.
- **Sicurezza**: hard guards live **in the tools** (scope-guard, pacing, confirm-tiers), not in
  the model. Empty `scope.json` = fail-closed. Third-party binaries only via the gated runner.

## Requirements

- Node.js >= 22
- DeepSeek Harness (DSH), tested baseline `dsh-v0.1.1-rc.2`

## Install

```bash
# npm (recommended)
dsh plugin --profile web add dsh-stavros

# or from GitHub (needs the allowBuilds trust step — see below)
dsh plugin --profile web add github:<you>/dsh-stavros

# or from a tarball / local dir
dsh plugin --profile web add ./dsh-stavros-0.1.0.tgz
```

> Git installs: pnpm users — pnpm >= 10 refuses to run `prepare` on git dependencies by default.
> On the first `add`, copy the package key printed by pnpm into the profile's `pnpm-workspace.yaml`
> `allowBuilds:` (e.g. `dsh-stavros: true`) and re-run `add`. Pin a commit for trust.

## First run (5 minutes)

1. **Create your engagement directory** — this is your workspace; the plugin hydrates its
   assets there and writes `reports/` next to it:

   ```bash
   mkdir ~/engagements/example && cd ~/engagements/example
   ```

2. **Start dsh from that directory**, then **compile `scope.json`** (created fail-closed on
   first boot; fill in only what you are authorized to test):

   ```json
   {
     "allowed_hosts": ["target.com", "api.target.com"],
     "allowed_ips": ["127.0.0.1", "10.0.0.0/8"],
     "max_requests_per_second": 2
   }
   ```

3. **Sanity-check the guard** (must exit non-zero until you compile scope):

   ```bash
   node tools/scope-guard.js check https://target.com
   ```

4. Ask, e.g.: *"Stavros, assess https://target.com — full web pentest"*. Stavros reads
   `knowledge.md` + `scope.json`, spawns recon → mapper → testers → reporter (stage gates +
   coverage matrix), and writes findings to `reports/findings.jsonl`.

Optional: `auth.json` (identities for the authenticated pass), `wifi-scope.json` (wireless mode),
`c2.json` (listener profiles) — copy the templates from `templates/`.

## How it works

On load, the plugin **hydrates** its packaged assets (`tools/`, `knowledge.md`, `refs/`,
`skills/`, `subagents/`) into the current workspace — merge-only, never overwrites your data —
and seeds an empty `scope.json` when none exists (fail-closed). The persona (via
`cordis.patch.yml`) instructs the orchestrator to read `{{cwd}}/knowledge.md` + `scope.json`,
spawn specialists from `{{cwd}}/subagents/*.md`, and drive the guarded tools.

`stavros_*` model-facing tools (12 shipped in v0.1: scope_check, repeater, run,
analyze_bundle, record_finding, verify_finding, jwt, oob, map, gate, coverage, gen_poc) are thin
wrappers over the same gated engines — the hard guards cannot be bypassed from the wrapper.

## Security model (read this)

- **`scope.json` is the written authorization.** Guarded tools refuse anything not listed there;
  empty = blocked. `run.js`/`repeater.js`/`oob.js`/`msf.js`/`sliver.js`/`wifi.js` enforce scope
  and confirm-tiers in code, independently of the model.
- **Default is non-destructive.** Destructive/high-impact actions (deletes, DoS, spraying real
  accounts, persistence, lateral movement) require the user's explicit in-session confirmation
  for *that* action.
- **No exploit code ships here.** Third-party binaries and operator artifacts stay out of the
  package; the harness runs them only through the gated runner.
- The fail-closed property is tested in CI (`verify` job): an empty `scope.json` must block.

## Development

```bash
npm install && npm run build   # tsc → lib/
npm pack                       # inspect the tarball contents

# end-to-end smoke test on a throwaway profile (needs an LLM key exported):
#   export ORCAROUTER_API_KEY=...     (or B_AI_API_KEY=...)
#   dsh plugin --profile dsh-stavros-test add ./dsh-stavros-0.1.0.tgz
bash scripts/smoke-test.sh     # boots headless, expects PLUGIN_OK + 6/6 hydration + fail-closed

# manual checks
dsh --profile dsh-stavros-test --dump-config | grep -A1 "name: dsh-stavros"

# cleanup after testing
rm -rf ~/.dsh/profiles/dsh-stavros-test
```

### Bundle anatomy (for maintainers — lessons from real validation)

- A profile created with `dsh plugin add` only has `dsh-base`, which is **not enough to run an
  app**: for headless boot declare `@deepseek-ai/dsh-headless` in the profile bundles too
  (`scripts/smoke-test.sh` does this automatically; the module resolves from the shared
  `$DSH_HOME/profiles` hoisted store).
- The bundle patch must contain a **mount row for the plugin itself**
  (`- insert: → - id: dsh-stavros, name: dsh-stavros`): without it the loader never runs the
  package's `apply()`. Patch rows are top-level overrides (must match existing base ids) or
  nested inserts under `- insert:`.
- The persona goes in the `config.persona` of the existing `system-prompt` row — **not** by
  inserting a second `@deepseek-ai/dsh-persona` (already loaded by dsh-base → "deployment:persona
  already registered").
- `dsh-base` already provides bash, fs, jobs, skills, subagents, plan-mode and compaction:
  the patch adds only what's missing (persona, skill dir, tool registrations).

## Release

Tag → CI publishes npm + GitHub Release automatically:

```bash
npm version patch
git push --tags
```

Requires the `NPM_TOKEN` secret (npm **Automation** token) in repository secrets and the
`npm-publish` environment (optional: required reviewers).

## Attribution & license

MIT. `refs/`, `skills/pentest-playbook` and parts of the persona are adapted from
[SeaOf0/dsh-redteam-model](https://github.com/SeaOf0/dsh-redteam-model) (MIT) and from the
StavrosRedTeamer project. The `tools/` suite is the runtime-agnostic engine shared with
StavrosRedTeamer (MIT). See `LICENSE`.
