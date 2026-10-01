#!/usr/bin/env bash
# End-to-end test of the change workflow against a local stand-in for the
# Cloudflare API (tests/e2e/fake_cloudflare.py). Nothing real is touched.
#
#   1. apply domains/example.com from scratch
#   2. re-plan: must say "Nothing will change" (no flapping fields)
#   3. make "dashboard" edits behind Terraform's back
#   4. drift check must list exactly those edits
#   5. edit the YAML like a pull request would
#   6. plan summary must show the PR changes, the drift, and mark the reverts
#   7. apply, then re-plan: must say "Nothing will change" again
#
# Needs: terraform (or TF=tofu), python3 with PyYAML, make, curl.
#   bash tests/e2e/run.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TF="${TF:-terraform}"
PORT="${E2E_PORT:-18787}"
WORK="$(mktemp -d)"
API="http://127.0.0.1:${PORT}/client/v4"
Z="0123456789abcdef0123456789abcdef"
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"
export CLOUDFLARE_API_TOKEN="e2e-test-token-not-real-0000000000000000"
unset CI || true   # local backend is refused in CI mode; this test is self-contained

python3 "$REPO/tests/e2e/fake_cloudflare.py" "$PORT" "$WORK/requests.log" > "$WORK/server.out" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 1 30); do curl -sf --noproxy '*' "$API/__dump" >/dev/null && break; sleep 0.2; done

cp -r "$REPO" "$WORK/repo"
cd "$WORK/repo"
rm -rf .state domains/*/.terraform domains/*/plan.* account/.terraform
D=domains/example.com
printf 'provider "cloudflare" {\n  base_url = "%s"\n}\n' "$API" > "$D/provider_override.tf"
MK="make -s TF=$TF BACKEND=local"

pass() { printf '  \033[32mok\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; echo "----- output -----"; cat "$2"; exit 1; }
expect() { grep -qF -- "$2" "$3" && pass "$1" || fail "$1 (expected: $2)" "$3"; }
reject() { grep -qF -- "$2" "$3" && fail "$1 (did not expect: $2)" "$3" || pass "$1"; }

echo "1. first apply"
$MK plan D=example.com > out1.txt 2>&1 || fail "plan" out1.txt
expect "plan lists new records" "ADD      DNS A \`api.example.com\`" out1.txt
YES=1 $MK apply D=example.com > out1a.txt 2>&1 || fail "apply" out1a.txt
expect "apply finished" "Applied." out1a.txt

echo "2. re-plan after apply"
$MK plan D=example.com > out2.txt 2>&1 || fail "plan" out2.txt
expect "nothing left to change" "Nothing will change" out2.txt

echo "3. dashboard edits"
python3 - "$API" "$Z" <<'EOF'
import json, sys, urllib.request
api, z = sys.argv[1], sys.argv[2]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def post(path, body):
    op.open(urllib.request.Request(api + path, data=json.dumps(body).encode(), method="POST"))
st = json.load(op.open(api + "/__dump"))["result"]["store"]
dns = st[f"/zones/{z}/dns_records"]
vpn = [k for k, v in dns.items() if v["name"] == "vpn.example.com"][0]
post("/__patch", {"coll": f"/zones/{z}/dns_records", "id": vpn, "fields": {"content": "198.51.100.99"}})
rs = st[f"/zones/{z}/rulesets"]
cid = [k for k, v in rs.items() if v["phase"] == "http_request_firewall_custom"][0]
rules = rs[cid]["rules"]
rules[2]["expression"] = '(http.request.uri.path eq "/wp-login.php") and ip.src ne 203.0.113.1'
post("/__patch", {"coll": f"/zones/{z}/rulesets", "id": cid, "fields": {"rules": rules}})
post("/__setting", {"zone": z, "id": "ssl", "value": "flexible"})
EOF
pass "edited a DNS record, a WAF rule and the SSL mode outside Git"

echo "4. drift check"
set +e; $MK drift D=example.com DRIFT_EXIT=1 > out4.txt 2>&1; rc=$?; set -e
[ $rc -eq 2 ] && pass "drift check exits 2" || fail "drift check exit code $rc" out4.txt
expect "drift: DNS" "content: \`198.51.100.5\` -> \`198.51.100.99\`" out4.txt
expect "drift: WAF" "and ip.src ne 203.0.113.1" out4.txt
expect "drift: SSL" "value: \`strict\` -> \`flexible\`" out4.txt
reject "drift lists only real edits" "api.example.com" out4.txt

echo "5. pull request edits"
sed -i 's/content: 203.0.113.20/content: 203.0.113.21/' "$D/dns/a.yaml"
python3 - "$D" <<'EOF'
import sys, yaml
d = sys.argv[1]
p = f"{d}/waf/custom-rules.yaml"
text = open(p).read()
header = "".join(l for l in text.splitlines(True) if l.startswith("#"))
rules = yaml.safe_load(text)
rules[1]["action"] = "managed_challenge"
open(p, "w").write(header + yaml.safe_dump(rules, sort_keys=False))
open(f"{d}/dns/mx.yaml", "w").write("# all MX records removed in this test\n")
EOF
pass "changed a record, a rule action, removed the MX record"

echo "6. pull request plan"
$MK plan D=example.com > out6.txt 2>&1 || fail "plan" out6.txt
expect "PR change: DNS" "content: \`203.0.113.20\` -> \`203.0.113.21\`" out6.txt
expect "PR change: WAF action" "action \`block\` -> \`managed_challenge\`" out6.txt
expect "PR change: delete MX" "DELETE   DNS MX" out6.txt
expect "warning for MX delete" "can stop a website or e-mail from working" out6.txt
expect "drift section" "CHANGED OUTSIDE GIT" out6.txt
expect "revert marked" "this undoes the dashboard change" out6.txt
expect "markdown summary saved" "#### Will change in Cloudflare" "$D/plan-summary.md"

echo "7. apply and re-plan"
echo "wrong" | $MK apply D=example.com > out7a.txt 2>&1 && fail "wrong confirmation must cancel" out7a.txt || true
expect "wrong confirmation cancels" "Cancelled. Nothing was changed." out7a.txt
echo "example.com" | $MK apply D=example.com > out7b.txt 2>&1 || fail "apply" out7b.txt
$MK plan D=example.com > out7c.txt 2>&1 || fail "plan" out7c.txt
expect "clean after apply" "Nothing will change" out7c.txt
set +e; $MK drift D=example.com DRIFT_EXIT=1 > out7d.txt 2>&1; rc=$?; set -e
[ $rc -eq 0 ] && pass "no drift after apply" || fail "drift after apply ($rc)" out7d.txt

echo "All end-to-end checks passed."
