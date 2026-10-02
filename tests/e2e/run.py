#!/usr/bin/env python3
"""
End-to-end test of the change workflow against a local stand-in for the
Cloudflare API (tests/e2e/fake_cloudflare.py). Nothing real is touched.

  1. apply domains/example.com from scratch
  2. re-plan: must say "Nothing will change" (no flapping fields)
  3. make "dashboard" edits behind Terraform's back
  4. drift check must list exactly those edits
  5. edit the YAML like a pull request would
  6. plan summary must show the PR changes, the drift, and mark the reverts
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


def ok(msg):
    print(f"  \033[32mok\033[0m {msg}")


def fail(msg, output=""):
    print(f"  \033[31mFAIL\033[0m {msg}")
    if output:
        print("----- output -----")
        print(output)
    sys.exit(1)


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
    shutil.copytree(REPO, work_repo, ignore=shutil.ignore_patterns(".git"))
    for p in [work_repo / ".state", work_repo / "account" / ".terraform",
              *work_repo.glob("domains/*/.terraform"), *work_repo.glob("domains/*/plan.*")]:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        elif p.exists():
            p.unlink()

    d = work_repo / "domains" / "example.com"
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
    if rc != 0:
        fail("plan", out)
    expect("plan lists new records", "ADD      DNS A `api.example.com`", out)
    rc, out = cf("apply", "example.com", "--yes")
    if rc != 0:
        fail("apply", out)
    expect("apply finished", "Applied.", out)

    print("2. re-plan after apply")
    rc, out = cf("plan", "example.com", "--backend", "local")
    if rc != 0:
        fail("plan", out)
    expect("nothing left to change", "Nothing will change", out)

    print("3. dashboard edits")
    make_dashboard_edits()
    ok("edited a DNS record, a WAF rule and the SSL mode outside Git")

    print("4. drift check")
    rc, out = cf("drift", "example.com", "--backend", "local", "--drift-exit")
    ok("drift check exits 2") if rc == 2 else fail(f"drift check exit code {rc}", out)
    expect("drift: DNS", "content: `198.51.100.5` -> `198.51.100.99`", out)
    expect("drift: WAF", "and ip.src ne 203.0.113.1", out)
    expect("drift: SSL", "value: `strict` -> `flexible`", out)
    reject("drift lists only real edits", "api.example.com", out)

    print("5. pull request edits")
    make_pr_edits(d)
    ok("changed a record, a rule action, removed the MX record")

    print("6. pull request plan")
    rc, out = cf("plan", "example.com", "--backend", "local")
    if rc != 0:
        fail("plan", out)
    expect("PR change: DNS", "content: `203.0.113.20` -> `203.0.113.21`", out)
    expect("PR change: WAF action", "action `block` -> `managed_challenge`", out)
    expect("PR change: delete MX", "DELETE   DNS MX", out)
    expect("warning for MX delete", "can stop a website or e-mail from working", out)
    expect("drift section", "CHANGED OUTSIDE GIT", out)
    expect("revert marked", "this undoes the dashboard change", out)
    expect("markdown summary saved", "#### Will change in Cloudflare", (d / "plan-summary.md").read_text(encoding="utf-8"))

    print("7. apply and re-plan")
    rc, out = cf("apply", "example.com", input_text="wrong\n")
    if rc == 0:
        fail("wrong confirmation must cancel", out)
    expect("wrong confirmation cancels", "Cancelled. Nothing was changed.", out)
    rc, out = cf("apply", "example.com", input_text="example.com\n")
    if rc != 0:
        fail("apply", out)
    rc, out = cf("plan", "example.com", "--backend", "local")
    if rc != 0:
        fail("plan", out)
    expect("clean after apply", "Nothing will change", out)
    rc, out = cf("drift", "example.com", "--backend", "local", "--drift-exit")
    ok("no drift after apply") if rc == 0 else fail(f"drift after apply ({rc})", out)

    print("All end-to-end checks passed.")


if __name__ == "__main__":
    main()
