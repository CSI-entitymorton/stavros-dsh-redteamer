## What & why

Briefly describe the change and the motivation. (Do not include engagement data or real
target names.)

## Checklist

- [ ] Change is within the project's boundaries (see [CONTRIBUTING](CONTRIBUTING.md)) —
      no exploit code, no av-evasion/darkweb content, no real credentials
- [ ] Build passes: `npm run build`
- [ ] Hermetic suite passes locally (new tools ship with a `test-*.js`)
- [ ] Fail-closed property preserved: empty `scope.json` blocks
- [ ] Conventional commit message (`feat(tools): …`, `fix(scope-guard): …`, `docs: …`)

## Test plan

What did you run to verify this works?
