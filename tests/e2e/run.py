#!/usr/bin/env python3
"""
End-to-end test of the change workflow against a local stand-in for the
Cloudflare API (tests/e2e/fake_cloudflare.py). Nothing real is touched.

  1. apply domains/example.com from scratch
  2. re-plan: must say "Nothing will change" (no flapping fields)
  3. make "dashboard" edits behind Terraform's back
  4. deviation check must list exactly those edits
  5. edit the YAML like a pull request would
  6. plan summary must show the PR changes, the deviation, and mark the reverts
  7. apply, then re-plan: must say "Nothing will change" again

Needs: terraform (or TF=tofu), python3 with PyYAML.
    python3 tests/e2e/run.py
"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent.parent
TF = os.environ.get("TF", "terraform")
PORT = int(os.environ.get("E2E_PORT", "18787"))
ZONE = "0123456789abcdef0123456789abcdef"
API = f"http://127.0.0.1:{PORT}/client/v4"


def _colour(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def ok(msg):
    print(f"  {_colour(32, 'ok')} {msg}")


def fail(msg, output=""):
    print(f"  {_colour(31, 'FAIL')} {msg}")
    if output:
        print("----- output -----")
        print(output)
    sys.exit(1)


def run_or_fail(label, rc, out):
    if rc != 0:
        fail(label, out)


def expect(msg, needle, haystack):
    ok(msg) if needle in haystack else fail(f"{msg} (expected: {needle})", haystack)


def reject(msg, needle, haystack):
    fail(f"{msg} (did not expect: {needle})", haystack) if needle in haystack else ok(msg)


def extend_proxy_bypass(name):
    existing = os.environ.get(name)
    return "127.0.0.1,localhost" + (f",{existing}" if existing else "")


def no_proxy_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def wait_ready(tries=30):
    opener = no_proxy_opener()
    for _ in range(tries):
        try:
            opener.open(f"{API}/__dump", timeout=1)
            return
        except urllib.error.URLError:
            time.sleep(0.2)
    sys.exit("fake Cloudflare server did not start")


def make_dashboard_edits():
    """Edit live "Cloudflare" state directly, bypassing Terraform — simulates
    someone using the dashboard instead of this repository."""
    opener = no_proxy_opener()

    def post(path, body):
        opener.open(urllib.request.Request(API + path, data=json.dumps(body).encode(), method="POST"))

    store = json.load(opener.open(f"{API}/__dump"))["result"]["store"]
    dns = store[f"/zones/{ZONE}/dns_records"]
    vpn = next(k for k, v in dns.items() if v["name"] == "vpn.example.com")
    post("/__patch", {"coll": f"/zones/{ZONE}/dns_records", "id": vpn, "fields": {"content": "198.51.100.99"}})
    rulesets = store[f"/zones/{ZONE}/rulesets"]
    cid = next(k for k, v in rulesets.items() if v["phase"] == "http_request_firewall_custom")
    rules = rulesets[cid]["rules"]
    rules[2]["expression"] = '(http.request.uri.path eq "/wp-login.php") and ip.src ne 203.0.113.1'
    post("/__patch", {"coll": f"/zones/{ZONE}/rulesets", "id": cid, "fields": {"rules": rules}})
    post("/__setting", {"zone": ZONE, "id": "ssl", "value": "flexible"})


def make_pr_edits(domain_dir):
    """Edit the YAML like a pull request would."""
    a_yaml = domain_dir / "dns" / "a.yaml"
    a_yaml.write_text(a_yaml.read_text(encoding="utf-8").replace("content: 203.0.113.20", "content: 203.0.113.21"),
                      encoding="utf-8")
    p = domain_dir / "waf" / "custom-rules.yaml"
    text = p.read_text(encoding="utf-8")
    header = "".join(l for l in text.splitlines(True) if l.startswith("#"))
    rules = yaml.safe_load(text)
    rules[1]["action"] = "managed_challenge"
    p.write_text(header + yaml.safe_dump(rules, sort_keys=False), encoding="utf-8")
    (domain_dir / "dns" / "mx.yaml").write_text("# all MX records removed in this test\n", encoding="utf-8")


def main():
    work = Path(tempfile.mkdtemp())
    log = open(work / "server.out", "w")
    server = subprocess.Popen(
        [sys.executable, str(REPO / "tests" / "e2e" / "fake_cloudflare.py"), str(PORT), str(work / "requests.log")],
        stdout=log, stderr=subprocess.STDOUT)

    def cleanup():
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        log.close()
        shutil.rmtree(work, ignore_errors=True)

    atexit.register(cleanup)
    wait_ready()

    work_repo = work / "repo"
    shutil.copytree(REPO, work_repo, ignore=shutil.ignore_patterns(".git", ".venv", "graphify-out", "__pycache__", "backend.hcl", ".env", ".env.*", ".terraform", ".state", ".export"))
    for p in [work_repo / ".state", work_repo / "account" / ".terraform",
              *work_repo.glob("domains/*/.terraform"), *work_repo.glob("domains/*/plan.*")]:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        elif p.exists():
            p.unlink()

    d = work_repo / "domains" / "example.com"
    shutil.copytree(work_repo / "tests" / "fixtures" / "domains" / "example.com", d)
    (d / "provider_override.tf").write_text(f'provider "cloudflare" {{\n  base_url = "{API}"\n}}\n', encoding="utf-8")

    env = dict(os.environ)
    env["TF"] = TF
    env["NO_PROXY"] = extend_proxy_bypass("NO_PROXY")
    env["no_proxy"] = extend_proxy_bypass("no_proxy")
    env["CLOUDFLARE_API_TOKEN"] = "e2e-test-token-not-real-0000000000000000"
    env.pop("CI", None)  # local backend is refused in CI mode; this test is self-contained

    def cf(*args, input_text=None):
        proc = subprocess.run([sys.executable, str(work_repo / "cf.py"), *args],
                              cwd=work_repo, env=env, capture_output=True, text=True, input=input_text)
        return proc.returncode, proc.stdout + proc.stderr

    print("1. first apply")
    rc, out = cf("plan", "example.com", "--backend", "local")
    run_or_fail("plan", rc, out)
    expect("plan lists new records", "ADD      DNS A `api.example.com`", out)
    rc, out = cf("apply", "example.com", "--yes")
    run_or_fail("apply", rc, out)
    expect("apply finished", "Applied.", out)

    print("2. re-plan after apply")
    rc, out = cf("plan", "example.com", "--backend", "local")
    run_or_fail("plan", rc, out)
    expect("nothing left to change", "Nothing will change", out)

    print("3. dashboard edits")
    make_dashboard_edits()
    ok("edited a DNS record, a WAF rule and the SSL mode outside Git")

    print("4. deviation check")
    rc, out = cf("deviation-check", "example.com", "--backend", "local", "--deviation-exit")
    ok("deviation check exits 2") if rc == 2 else fail(f"deviation check exit code {rc}", out)
    expect("deviation: DNS", "content: `198.51.100.5` -> `198.51.100.99`", out)
    expect("deviation: WAF", "and ip.src ne 203.0.113.1", out)
    expect("deviation: SSL", "value: `strict` -> `flexible`", out)
    reject("deviation lists only real edits", "api.example.com", out)

    print("4b. deviation fingerprint is stable across runs")
    # scripts/deviation_autofix.py decides whether it is safe to commit a
    # resync by fingerprinting the reported deviation before the export and
    # again afterwards, and refusing if it moved. That only works if a
    # repeated refresh-only plan over unchanged Cloudflare state produces the
    # same resource_drift -- the real Terraform behaviour the autofix unit
    # tests have to stub out. Prove it here, where Terraform is real.
    sys.path.insert(0, str(work_repo / "scripts"))
    import deviation_autofix as autofix  # noqa: E402
    first = autofix.drift_fingerprint(d)
    if not first:
        fail("no deviation fingerprint after a deviation was reported")
    rc, out = cf("deviation-check", "example.com", "--backend", "local", "--deviation-exit")
    if rc != 2:
        fail(f"second deviation check exit code {rc}", out)
    second = autofix.drift_fingerprint(d)
    if first != second:
        fail("deviation fingerprint changed between two identical checks; the "
             "autofix would refuse every resync")
    ok("two identical checks agree, so a resync is allowed to proceed")

    print("5. pull request edits")
    make_pr_edits(d)
    ok("changed a record, a rule action, removed the MX record")

    print("6. pull request plan")
    rc, out = cf("plan", "example.com", "--backend", "local")
    run_or_fail("plan", rc, out)
    expect("PR change: DNS", "content: `203.0.113.20` -> `203.0.113.21`", out)
    expect("PR change: WAF action", "action `block` -> `managed_challenge`", out)
    expect("PR change: delete MX", "DELETE   DNS MX", out)
    expect("warning for MX delete", "can stop a website or e-mail from working", out)
    expect("deviation section", "CHANGED OUTSIDE GIT", out)
    expect("revert marked", "this undoes the dashboard change", out)
    expect("markdown summary saved", "#### Will change in Cloudflare", (d / "plan-summary.md").read_text(encoding="utf-8"))

    print("7. apply and re-plan")
    rc, out = cf("apply", "example.com", input_text="wrong\n")
    if rc == 0:
        fail("wrong confirmation must cancel", out)
    expect("wrong confirmation cancels", "Cancelled. Nothing was changed.", out)
    rc, out = cf("apply", "example.com", input_text="example.com\n")
    run_or_fail("apply", rc, out)
    rc, out = cf("plan", "example.com", "--backend", "local")
    run_or_fail("plan", rc, out)
    expect("clean after apply", "Nothing will change", out)
    rc, out = cf("deviation-check", "example.com", "--backend", "local", "--deviation-exit")
    ok("no deviation after apply") if rc == 0 else fail(f"deviation after apply ({rc})", out)

    print("8. direct Terraform rejects malformed and wrong-shaped service YAML")
    for filename, text in (("dns/a.yaml", "bad: ["), ("waf/custom-rules.yaml", "{}")):
        target = d / filename
        original = target.read_bytes()
        try:
            target.write_text(text, encoding="utf-8")
            result = subprocess.run([TF, f"-chdir={d}", "plan", "-refresh=false", "-input=false", "-no-color"],
                                    cwd=work_repo, env=env, capture_output=True, text=True)
            if result.returncode == 0:
                fail(f"direct Terraform accepted invalid {filename}", result.stdout + result.stderr)
            expect("direct validation failure", "Error:", result.stdout + result.stderr)
        finally:
            target.write_bytes(original)
    rc, out = cf("init", "account", "--backend", "local")
    run_or_fail("account init", rc, out)
    for filename, text in (("lists/ip.yaml", "bad: ["), ("lists/ip.yaml", "[]"), ("waf/custom-rules.yaml", "{}")):
        target = work_repo / "account" / filename
        original = target.read_bytes()
        try:
            target.write_text(text, encoding="utf-8")
            result = subprocess.run([TF, f"-chdir={work_repo / 'account'}", "plan", "-refresh=false", "-input=false", "-no-color"],
                                    cwd=work_repo, env=env, capture_output=True, text=True)
            if result.returncode == 0:
                fail(f"direct Terraform accepted invalid account {filename}", result.stdout + result.stderr)
            expect("direct account validation failure", "Error:", result.stdout + result.stderr)
        finally:
            target.write_bytes(original)

    print('9. reconcile dashboard record edits, additions, and deletions without live writes')
    from unittest.mock import patch
    from exporting import client as export_client
    from exporting.services import ZoneExport
    from exporting.output import write_imports
    from workflow.reconciliation import reconcile, state_bindings
    from workflow.inventory import collect, require_complete, record, differences
    opener = no_proxy_opener()
    def request(method, path, value=None):
        return json.load(opener.open(urllib.request.Request(API + path, method=method,
                            data=json.dumps(value).encode() if value is not None else None)))['result']
    with patch.dict(os.environ, env), patch.object(export_client, 'API', API):
        bindings = state_bindings(d)
        store = request('GET', '/__dump')['store']
        dns_path = f'/zones/{ZONE}/dns_records'
        dns = store[dns_path]
        existing = next(item for item in dns.values() if item['type'] == 'A')
        removed = next(item for item in dns.values() if item['type'] == 'CNAME')
        request('POST', '/__patch', {'coll': dns_path, 'id': existing['id'], 'fields': {'content': '198.51.100.101'}})
        request('DELETE', dns_path + '/' + removed['id'])
        created = request('POST', dns_path, {'type': 'A', 'name': existing['name'], 'content': '192.0.2.10', 'ttl': 300, 'proxied': False})
        exporter = ZoneExport(export_client.Client('fixture'), ZONE, 'example.com', 'pro', bindings)
        exporter.dns()
        for filename, data in exporter.files.items():
            (d / filename).write_text(yaml.safe_dump(data, sort_keys=False), encoding='utf-8')
        write_imports(d / 'imports.tf', exporter.imports, bindings)
        inventory = collect(export_client.Client('fixture'), d)
        require_complete(inventory)
        before = request('GET', '/__dump')['store']
        log_start = (work / 'requests.log').stat().st_size
        reconcile(d, inventory)
        after = request('GET', '/__dump')['store']
        if before != after:
            fail('state-only reconciliation changed the dashboard')
        calls = (work / 'requests.log').read_bytes()[log_start:].decode('utf-8').splitlines()
        mutations = [call for call in calls if not call.startswith('GET ') and 'dry_run' not in call and 'dry-run' not in call]
        if mutations:
            fail('reconciliation sent a live write request', '\n'.join(mutations))
        current = state_bindings(d)
        if f"{ZONE}/{created['id']}" not in current or f"{ZONE}/{removed['id']}" in current:
            fail('new/deleted dashboard identities were not reconciled')
        if current[f"{ZONE}/{existing['id']}"] != bindings[f"{ZONE}/{existing['id']}"]:
            fail('existing record changed Terraform identity')
        refreshed = collect(export_client.Client('fixture'), d)
        require_complete(refreshed)
        if differences(refreshed, record(inventory)):
            fail('state reconciliation caused an inventory loop')
        (d / 'imports.tf').unlink()
        ok('dashboard unchanged; new record imported, deletion forgotten, existing identity retained; no inventory loop')
    print("All end-to-end checks passed.")


if __name__ == "__main__":
    main()
