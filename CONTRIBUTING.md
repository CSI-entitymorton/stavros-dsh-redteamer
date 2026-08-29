# Contributing

Thanks for considering a contribution to `stavros-dsh-redteamer`. This is an
**authorized-only** red-team harness: before opening a PR, make sure your
contribution fits the project's boundaries (see [Security model](README.md#security-model-read-this)).

## What's welcome

- **Tools** — new zero-dependency, scope-guarded tool modules in `tools/` (with a
  hermetic `test-*.js` next to them).
- **Subagents & persona** — new specialist personas in `subagents/` or improvements to
  the orchestrator persona in `cordis.patch.yml`.
- **Knowledge** — corrections/additions to `refs/` or `knowledge.md`.
- **Docs, CI, packaging, bug fixes** — anything that makes the plugin more reliable or
  easier to use.

Please **do not** contribute:

- Exploit code, av-evasion/darkweb content, or pre-canned attack payloads (nothing of
  this ships in the package — third-party binaries run only through the gated runner).
- Real credentials, engagement data, or program notes from live engagements.
- New runtime dependencies for the tool suite (it is intentionally zero-dependency).

## Setup & workflow

```bash
npm ci && npm run build        # install + tsc → lib/
```

Every change must keep the suite green:

```bash
# hermetic suite (53 files; the 2 network-bound E2E are excluded from CI)
for t in tools/test-*.js; do
  case "$t" in tools/test-authn-depth.js|tools/test-mcp.js) continue;; esac
  node "$t" || echo "FAIL $t"
done

# fail-closed property: without scope.json every target action must be blocked
if node tools/scope-guard.js check https://example.com; then
  echo "FAIL: scope-guard is not fail-closed"; exit 1
fi
```

## Pull requests

1. Branch from `main`, keep the diff focused on one concern.
2. Use [conventional commits](https://www.conventionalcommits.org/) (`feat(tools): …`,
   `fix(scope-guard): …`, `docs: …`).
3. If you add a tool, add its hermetic test and make sure it passes without network
   access or LLM keys.
4. Make sure CI is green (build + fail-closed smoke + hermetic suite).

## Security

Found a vulnerability in the plugin itself? Do **not** open a public issue — see
[`SECURITY.md`](SECURITY.md) for the disclosure process.
