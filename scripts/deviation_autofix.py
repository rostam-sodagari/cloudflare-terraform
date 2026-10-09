#!/usr/bin/env python3
"""
Auto-remediation for deviation detection: when a root has deviated from
what the YAML says (a dashboard edit, usually), re-export it from the
live Cloudflare API and -- only if the result passes the exact same
structural and policy checks as any other change -- commit and push it
directly to main.

This is a deliberate trade-off, not an oversight: it bypasses human
review for deviation-sourced changes specifically. See
docs/14-deviation-detection.md for the guardrails and what it needs from
your branch protection settings. If the re-exported YAML fails
validation, nothing is pushed -- the caller (the deviation-detection
workflow) falls back to its usual "please review this" issue instead.

    CLOUDFLARE_API_TOKEN=... python3 scripts/deviation_autofix.py example.com
    CLOUDFLARE_API_TOKEN=... python3 scripts/deviation_autofix.py account
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import export_zone  # noqa: E402
from yamlio import dump_with_header, header_of  # noqa: E402


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def validate_export(path):
    target = "account" if path.name == "account" else str(path)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate.py"), target],
        cwd=ROOT, text=True
    )
    if result.returncode != 0:
        sys.exit("post-export validation failed; falling back to manual review")


def verify_live_state(root):
    result = subprocess.run(
        [sys.executable, str(ROOT / "cf.py"), "deviation-check", root, "--deviation-exit"],
        cwd=ROOT, capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.exit(
            "Cloudflare changed during export; refusing to commit an intermediate state. "
            "Run deviation detection again after the live state is stable.\n"
            + result.stdout + result.stderr
        )


def restrict_to_previously_managed(settings_file, previously_managed):
    """export_zone()'s settings() always pulls every setting it knows how to
    read -- right for a first adoption, wrong for a resync: it would start
    managing settings this repo was deliberately left alone ("leaving a
    setting out means this repo does not manage it, it is not reset" --
    settings/zone.yaml's own header). Drop anything the resync introduced
    that wasn't already tracked before this run."""
    if previously_managed is None:
        return  # no prior file: this is a first adoption, keep everything
    if not settings_file.exists():
        return
    text = settings_file.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        return
    restricted = {k: v for k, v in data.items() if k in previously_managed}
    if restricted == data:
        return
    dump_with_header(settings_file, restricted, header_of(settings_file))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="domain folder name, or 'account'")
    ap.add_argument("--bot-name", default="deviation-bot")
    ap.add_argument("--bot-email", default="deviation-bot@users.noreply.github.com")
    ap.add_argument("--branch", default="main")
    a = ap.parse_args()

    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        sys.exit("CLOUDFLARE_API_TOKEN is required")
    client = export_zone.Client(token)

    if a.root == "account":
        account_yaml = yaml.safe_load((ROOT / "account" / "account.yaml").read_text(encoding="utf-8")) or {}
        ns = argparse.Namespace(account_id=account_yaml.get("account_id"), plan=account_yaml.get("plan"))
        path = ROOT / "account"
        settings_file = None  # account/ has no equivalent blanket-fetched settings file
        previously_managed = None
        try:
            rc = export_zone.export_account(client, ns)
        except (PermissionError, RuntimeError) as e:
            sys.exit(f"export failed, falling back to manual review: {e}")
    else:
        domain_yaml = yaml.safe_load((ROOT / "domains" / a.root / "domain.yaml").read_text(encoding="utf-8")) or {}
        ns = argparse.Namespace(zone_id=domain_yaml.get("zone_id"), domain=a.root,
                                plan=domain_yaml.get("plan"), force=True)
        path = ROOT / "domains" / a.root
        settings_file = path / "settings" / "zone.yaml"
        if settings_file.exists():
            before = yaml.safe_load(settings_file.read_text(encoding="utf-8")) or {}
            previously_managed = set(before) if isinstance(before, dict) else set()
        else:
            previously_managed = None
        try:
            rc = export_zone.export_zone(client, ns)
        except (PermissionError, RuntimeError) as e:
            sys.exit(f"export failed, falling back to manual review: {e}")

    # export_zone()/export_account() already ran the validator (structural
    # checks + the policy.yaml gate) and returned its exit code. Reaching
    # here with rc != 0 means the re-exported YAML didn't pass -- do not
    # push something that fails the same checks a human PR would have to.
    if rc != 0:
        sys.exit("re-exported YAML failed validation; falling back to manual review")

    if settings_file is not None:
        restrict_to_previously_managed(settings_file, previously_managed)
    validate_export(path)
    verify_live_state(a.root)

    # imports.tf is for ADOPTING objects Terraform doesn't know about yet.
    # Everything here is already tracked in state (this is a resync, not a
    # first import), so an import block would be redundant at best.
    imports_tf = path / "imports.tf"
    if imports_tf.exists():
        imports_tf.unlink()

    rel = str(path.relative_to(ROOT)).replace("\\", "/")
    status = git("status", "--porcelain", "--", rel).stdout.strip()
    if not status:
        print(f"no change after export; {rel} already matches live Cloudflare")
        return

    git("config", "user.name", a.bot_name)
    git("config", "user.email", a.bot_email)
    git("add", "--", rel)
    changed_files = "\n".join(line[3:] for line in status.splitlines())
    message = (
        f"Sync {a.root} with live Cloudflare state (deviation detected)\n\n"
        f"Auto-committed by deviation detection: the YAML below was out of date "
        f"with what's actually configured in Cloudflare. The re-exported version "
        f"passed the same structural and policy checks a pull request would need "
        f"to pass.\n\nFiles changed:\n{changed_files}\n"
    )
    commit = git("commit", "-m", message)
    if commit.returncode != 0:
        sys.exit(f"commit failed: {commit.stdout}\n{commit.stderr}")
    push = git("push", "origin", f"HEAD:{a.branch}")
    if push.returncode != 0:
        sys.exit(f"push failed (check that {a.bot_name} is allowed to bypass branch "
                 f"protection on {a.branch} -- see docs/14-deviation-detection.md): "
                 f"{push.stdout}\n{push.stderr}")
    print(f"committed and pushed: {rel} synced to live Cloudflare state")


if __name__ == "__main__":
    main()
