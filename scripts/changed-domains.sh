#!/usr/bin/env bash
# Print a JSON array of roots to PLAN for changes since $1 (git ref).
#   Roots: "account" and every domains/<name>.
#   Skipped: folders starting with _ (templates) and domains whose
#   domain.yaml says "example: true" (sample data with fake IDs).
#   A change under modules/ affects every root. "account" comes first so
#   lists exist before domains that use them.
# Pass "--all" instead of a ref to list every root (used by the drift check).
set -euo pipefail
cd "$(dirname "$0")/.."

all_roots() {
  grep -qE '^example:[[:space:]]*true' account/account.yaml 2>/dev/null || echo account
  for d in domains/*/; do
    d=${d%/}; n=${d#domains/}
    [[ $n == _* ]] && continue
    grep -qE '^example:[[:space:]]*true' "$d/domain.yaml" 2>/dev/null && continue
    echo "$n"
  done
}

if [[ "${1:-}" == "--all" ]]; then
  list=$(all_roots)
else
  base="${1:-origin/main}"
  changed=$(git diff --name-only "$base"...HEAD 2>/dev/null || git diff --name-only HEAD~1 HEAD 2>/dev/null || true)
  if [[ -z "$changed" ]] || grep -qE '^(modules|scripts)/' <<<"$changed"; then
    list=$(all_roots)   # shared code changed, or history unavailable: plan everything
  else
    wanted=$( (grep -qE '^account/' <<<"$changed" && echo account) || true
              grep -oE '^domains/[^/]+' <<<"$changed" | cut -d/ -f2 | sort -u || true)
    list=$(all_roots | grep -Fxf <(printf '%s\n' $wanted) || true)
  fi
fi
printf '%s\n' $list | jq -R . | jq -sc 'map(select(length > 0))'
