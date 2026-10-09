#!/usr/bin/env python3
"""
Auto-remediation for deviation detection: re-export a deviated root from the
live Cloudflare API and, only if the result passes the same structural and
policy checks as any pull request, commit and push it straight to main.

Bypassing review is deliberate. The guardrails that make that safe, and the
branch protection it needs, are in docs/14-deviation-detection.md. If any
check here fails nothing is pushed, and the caller falls back to its
"please review this" issue.

    CLOUDFLARE_API_TOKEN=... python3 scripts/deviation_autofix.py example.com
    CLOUDFLARE_API_TOKEN=... python3 scripts/deviation_autofix.py account
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import export_zone  # noqa: E402
import record_docs  # noqa: E402
from yamlio import dump_with_header, header_of  # noqa: E402

# Only adopts objects not yet in state, so a resync removes a stale one.
ALLOWED_DELETIONS = {"imports.tf"}


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


def run_deviation_check(root):
    """`cf.py deviation-check <root> --deviation-exit`, which (re)writes
    <root dir>/deviation.json. Exit code 0 = clean, 2 = deviation present;
    anything else is a real failure."""
    return subprocess.run(
        [sys.executable, str(ROOT / "cf.py"), "deviation-check", root, "--deviation-exit"],
        cwd=ROOT, capture_output=True, text=True
    )


def drift_fingerprint(root_dir):
    """Stable hash of the deviation reported for this root, or None if unavailable.

    Compared before and after the export. Requiring a *clean* re-check instead
    could never pass: refresh-only compares state with live Cloudflare, and
    re-exporting YAML does not touch state."""
    f = Path(root_dir) / "deviation.json"
    if not f.exists():
        return None
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    drift = data.get("resource_drift") or []
    return hashlib.sha256(
        json.dumps(drift, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_drift_unchanged(root, root_dir, before):
    result = run_deviation_check(root)
    if result.returncode not in (0, 2):
        sys.exit("deviation re-check failed, falling back to manual review:\n"
                 + result.stdout + result.stderr)
    after = drift_fingerprint(root_dir)
    if after != before:
        sys.exit(
            "Cloudflare changed while this resync was running; refusing to commit an "
            "intermediate state. Run deviation detection again once the live state is stable."
        )


def deleted_files(rel):
    """Files git sees as deleted under `rel`, ignoring ALLOWED_DELETIONS."""
    out = []
    for line in git("status", "--porcelain", "--", rel).stdout.splitlines():
        if not line.strip():
            continue
        xy, name = line[:2], line[3:].strip().strip('"')
        if "D" in xy and Path(name).name not in ALLOWED_DELETIONS:
            out.append(name)
    return out


def copy_yaml(staging, dest):
    """Copy only the YAML the export actually wrote into the live folder.

    Skips domain.yaml, which the exporter rewrites with `owner: change-me` and
    is not live state anyway. Skips files still byte-identical to _template:
    the exporter only rewrites what it has data for, and it does not cover
    every service, so a blank template must not overwrite a populated file.
    Exporter silence means "no information", never "delete what you have"."""
    template = ROOT / "domains" / "_template"
    copied, skipped = 0, []
    for src in sorted(Path(staging).rglob("*.yaml")):
        rel = src.relative_to(staging)
        if rel.as_posix() == "domain.yaml":
            continue
        tpl = template / rel
        if tpl.exists() and src.read_bytes() == tpl.read_bytes():
            skipped.append(rel.as_posix())
            continue
        target = Path(dest) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
        copied += 1
    if skipped:
        print(f"  left alone (nothing exported for them): {', '.join(skipped)}")
    return copied


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


def managed_keys(f):
    """The top-level keys a blanket-fetched settings file tracked before the
    resync, or None when the file doesn't exist yet (a first adoption)."""
    if not f.exists():
        return None
    data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    return set(data) if isinstance(data, dict) else set()


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

    path = ROOT / "account" if a.root == "account" else ROOT / "domains" / a.root
    if not path.is_dir():
        sys.exit(f"no such root: {path}")

    # The workflow has already run deviation-check; standalone runs have not.
    before_drift = drift_fingerprint(path)
    if before_drift is None:
        result = run_deviation_check(a.root)
        if result.returncode not in (0, 2):
            sys.exit("deviation check failed, falling back to manual review:\n"
                     + result.stdout + result.stderr)
        before_drift = drift_fingerprint(path)
        if before_drift is None:
            sys.exit("could not read the deviation report; falling back to manual review")

    before_docs = record_docs.harvest(path)

    if a.root == "account":
        # export_account() writes its files in place and never rebuilds the
        # folder, so there is nothing to stage.
        account_yaml = yaml.safe_load((path / "account.yaml").read_text(encoding="utf-8")) or {}
        ns = argparse.Namespace(account_id=account_yaml.get("account_id"), plan=account_yaml.get("plan"))
        try:
            rc = export_zone.export_account(client, ns)
        except (PermissionError, RuntimeError) as e:
            sys.exit(f"export failed, falling back to manual review: {e}")
        if rc != 0:
            sys.exit("re-exported YAML failed validation; falling back to manual review")
    else:
        domain_yaml = yaml.safe_load((path / "domain.yaml").read_text(encoding="utf-8")) or {}
        blanket = [path / "settings" / "zone.yaml",
                   path / "cache" / "settings.yaml",
                   path / "security" / "bot-management.yaml"]
        previously_managed = {f: managed_keys(f) for f in blanket}

        # The staging folder has to be named after the domain: validate.py
        # errors when domain.yaml's `name` doesn't match its folder name.
        staging_root = ROOT / ".export" / a.root / "resync"
        if staging_root.exists():
            shutil.rmtree(staging_root)   # our own scratch from an earlier run
        staging_root.mkdir(parents=True, exist_ok=True)
        staging = staging_root / a.root
        ns = argparse.Namespace(zone_id=domain_yaml.get("zone_id"), domain=a.root,
                                plan=domain_yaml.get("plan"), force=False, dest=staging)
        try:
            rc = export_zone.export_zone(client, ns)
        except (PermissionError, RuntimeError) as e:
            sys.exit(f"export failed, falling back to manual review: {e}")

        # Checked before the copy: a re-export that fails validation must not
        # reach the folder people edit, even uncommitted.
        if rc != 0:
            shutil.rmtree(staging_root, ignore_errors=True)
            sys.exit("re-exported YAML failed validation; falling back to manual review")

        record_docs.reinject(staging, before_docs)
        copy_yaml(staging, path)
        shutil.rmtree(staging_root, ignore_errors=True)
        for f, keys in previously_managed.items():
            restrict_to_previously_managed(f, keys)

    imports_tf = path / "imports.tf"
    if imports_tf.exists():
        imports_tf.unlink()

    rel = str(path.relative_to(ROOT)).replace("\\", "/")

    # ---- invariants: cheap checks first, live re-check last ----------------
    missing_docs = record_docs.lost(before_docs, path)
    if missing_docs:
        sys.exit("refusing to commit: the re-export dropped record documentation for "
                 + ", ".join(missing_docs)
                 + ". Falling back to manual review -- see docs/41-record-documentation.md")

    gone = deleted_files(rel)
    if gone:
        sys.exit("refusing to commit: the re-export would delete " + ", ".join(gone)
                 + ". Falling back to manual review.")

    validate_export(path)  # the live folder, now that docs are back

    status = git("status", "--porcelain", "--", rel).stdout.strip()
    if not status:
        print(f"no change after export; {rel} already matches live Cloudflare")
        return

    verify_drift_unchanged(a.root, path, before_drift)

    git("config", "user.name", a.bot_name)
    git("config", "user.email", a.bot_email)
    git("add", "--", rel)
    changed_files = "\n".join(line[3:] for line in status.splitlines())
    message = (
        f"Sync {a.root} with live Cloudflare state (deviation detected)\n\n"
        f"Auto-committed by deviation detection: the YAML below was out of date "
        f"with what's actually configured in Cloudflare. The re-exported version "
        f"passed the same structural and policy checks a pull request would need "
        f"to pass, kept every record documentation block, and deleted nothing."
        f"\n\nFiles changed:\n{changed_files}\n"
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
