#!/usr/bin/env bash
# Create domains/<name> from the template.
set -euo pipefail
name="${1:?domain}"; zone_id="${2:?zone id}"; plan="${3:?free|pro|business|enterprise}"
[[ "$zone_id" =~ ^[0-9a-f]{32}$ ]] || { echo "zone id must be 32 hex characters"; exit 1; }
[[ "$plan" =~ ^(free|pro|business|enterprise)$ ]] || { echo "plan must be free, pro, business or enterprise"; exit 1; }
root="$(cd "$(dirname "$0")/.." && pwd)"
dest="$root/domains/$name"
[[ -e "$dest" ]] && { echo "$dest already exists"; exit 1; }
cp -r "$root/domains/_template" "$dest"
rm -f "$dest/README.md"
cat > "$dest/domain.yaml" <<YAML
name: $name
zone_id: "$zone_id"
plan: $plan
owner: change-me
YAML
echo "Created $dest. Fill in the YAML files, then: make plan D=$name"
