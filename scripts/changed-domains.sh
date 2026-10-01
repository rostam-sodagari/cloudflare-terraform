#!/usr/bin/env bash
# Print a JSON array of roots affected by changes since $1 (git ref).
# Roots: "account" and every domains/<name> (folders starting with _ are skipped).
# A change under modules/ affects every root. "account" is listed first so
# lists exist before domains that reference them.
set -euo pipefail
base="${1:-origin/main}"
all="account
$(find domains -mindepth 1 -maxdepth 1 -type d ! -name '_*' -printf '%f\n' | sort)"
changed=$(git diff --name-only "$base"...HEAD 2>/dev/null || git diff --name-only HEAD~1 HEAD)
if grep -qE '^modules/' <<<"$changed"; then
  list="$all"
else
  list="$(grep -qE '^account/' <<<"$changed" && echo account || true)
$(grep -oE '^domains/[^/]+' <<<"$changed" | cut -d/ -f2 | grep -v '^_' | sort -u || true)"
fi
# Only roots that still exist (a deleted domain needs a manual destroy).
while read -r d; do
  [[ -z "$d" ]] && continue
  [[ "$d" == account || -d "domains/$d" ]] && echo "$d"
done <<<"$list" | jq -R . | jq -sc .
