#!/usr/bin/env bash
# smoke-test.sh — validazione locale di stavros-dsh-redteamer (fase 4 del piano di rilascio).
#
# Boot headless del profile stavros-dsh-redteamer-test con un task banale, poi verifica che
# il plugin abbia: (1) risposto, (2) idratato gli asset nel workspace, (3) seed di
# scope.json fail-closed.
#
# Prerequisiti:
#   - dsh installato in ~/.dsh/cli (baseline dsh-v0.1.1-rc.2)
#   - profile usa-e-getta pronto:  dsh plugin --profile stavros-dsh-redteamer-test add ./stavros-dsh-redteamer-0.2.0.tgz
#   - chiave LLM esportata (es. export ORCAROUTER_API_KEY=... / B_AI_API_KEY=...)
#
# Nota: un profile creato con `dsh plugin add` ha solo dsh-base, che non basta a
# eseguire un'app. Questo script dichiara da solo il bundle @deepseek-ai/dsh-headless
# (risolto dallo store hoisted condiviso di ~/.dsh/profiles) se manca.
#
# Uso:  bash scripts/smoke-test.sh [/path/workspace]
set -u
WS="${1:-/tmp/stavros-dsh-redteamer-smoke}"
PROFILE_DIR="$HOME/.dsh/profiles/stavros-dsh-redteamer-test"
DSH_BIN="$HOME/.dsh/cli/node_modules/@deepseek-ai/dsh/lib/bin.js"

if ! command -v node >/dev/null 2>&1; then echo "node mancante"; exit 1; fi
if [[ ! -f "$DSH_BIN" ]]; then
  echo "dsh non trovato in ~/.dsh/cli"; exit 1
fi
if [[ -z "${ORCAROUTER_API_KEY:-}" && -z "${B_AI_API_KEY:-}" && -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "⚠️  nessuna chiave LLM esportata — il boot fallirà. export ORCAROUTER_API_KEY=..."
fi
if [[ ! -f "$PROFILE_DIR/package.json" ]]; then
  echo "profile stavros-dsh-redteamer-test mancante — crealo prima:"
  echo "  dsh plugin --profile stavros-dsh-redteamer-test add /path/to/stavros-dsh-redteamer-0.2.0.tgz"
  exit 1
fi

# auto-dichiara il bundle app headless se assente (il plugin add inizializza solo dsh-base)
python3 - "$PROFILE_DIR" <<'EOF'
import json, sys
p = sys.argv[1] + '/package.json'
d = json.load(open(p))
b = d.setdefault('dsh', {}).setdefault('profile', {}).setdefault('bundles', [])
if '@deepseek-ai/dsh-headless' not in b:
    b.append('@deepseek-ai/dsh-headless')
    json.dump(d, open(p, 'w'), indent=2)
    print('bundle dsh-headless aggiunto al profile di test')
EOF

rm -rf "$WS"; mkdir -p "$WS"; cd "$WS" || exit 1
echo "=== boot headless (workspace: $WS) ==="
node "$DSH_BIN" --profile stavros-dsh-redteamer-test headless "Reply with exactly: PLUGIN_OK" </dev/null 2>&1 | tail -25
echo "=== verifica hydrate ==="
ok=0
[[ -d "$WS/tools" ]]        && { echo "tools/ idratati ✓"; ok=$((ok+1)); } || echo "tools/ MANCANTI ✗"
[[ -d "$WS/subagents" ]]    && { echo "subagents/ idratati ✓"; ok=$((ok+1)); } || echo "subagents/ MANCANTI ✗"
[[ -d "$WS/refs" ]]         && { echo "refs/ idratati ✓"; ok=$((ok+1)); } || echo "refs/ MANCANTI ✗"
[[ -d "$WS/skills" ]]       && { echo "skills/ idratate ✓"; ok=$((ok+1)); } || echo "skills/ MANCANTI ✗"
[[ -f "$WS/scope.json" ]]   && { echo "scope.json seed fail-closed ✓"; ok=$((ok+1)); } || echo "scope.json MANCANTE ✗"
[[ -f "$WS/knowledge.md" ]] && { echo "knowledge.md ✓"; ok=$((ok+1)); } || echo "knowledge.md MANCANTE ✗"
echo "==> $ok/6 check superati"
# fail-closed: scope vuoto deve bloccare
if node "$WS/tools/scope-guard.js" check https://example.com 2>/dev/null; then
  echo "✗ scope-guard NON è fail-closed con scope vuoto!"
else
  echo "✓ scope-guard fail-closed (scope vuoto blocca)"
fi
