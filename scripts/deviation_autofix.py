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
your branch protection settings. If any check below fails, nothing is
pushed -- the caller (the deviation-detection workflow) falls back to its
usual "please review this" issue instead.

Because nothing here is reviewed before it lands, the resync is built so
it *cannot* quietly damage the folder people edit:

  * It exports into a staging directory under .export/ instead of
    deleting and rebuilding domains/<name>/ (which would also take out
    the local .terraform/ cache and the provider lock file).
  * It carries every '## Owner/Purpose/Impact' record documentation block
    across the re-export (scripts/record_docs.py), because yaml.safe_dump
    cannot keep comments, and refuses to commit if any block went missing.
  * It copies only *.yaml forward -- main.tf, providers.tf and tests/ are
    never touched -- and refuses to commit if any file was deleted.
  * It re-checks the live state at the end and refuses to commit if
    Cloudflare changed while the export was running.

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

# A resync only ever rewrites YAML. imports.tf is the one exception: it
# exists to ADOPT objects Terraform doesn't know about yet, and everything
# here is already in state, so a stale one is removed rather than carried
# forward -- which is why it is exempt from the "nothing was deleted" check.
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
    """A stable hash of the deviation currently reported for this root, or
    None when no deviation.json is available.

    This is what makes the end-of-run check meaningful. The earlier version
    re-ran deviation-check and required a *clean* result, which could never
    happen: `terraform plan -refresh-only` compares Terraform's state with
    live Cloudflare, and re-exporting YAML does not touch state, so the same
    deviation was still there every time and the resync always aborted.
    Comparing the fingerprint before and after instead answers the question
    actually worth asking -- did anything change *while we were exporting*."""
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
    Anything the exporter doesn't produce -- main.tf, providers.tf, tests/,
    .terraform/, the provider lock -- is left exactly as it was.

    Two kinds of staged file are deliberately skipped:

    domain.yaml, because the exporter rewrites it with `owner: change-me` and
    drops any `example:` flag, none of which is live Cloudflare state. A
    dashboard edit cannot change a zone's identity, so the human-maintained
    file stays. If the zone's plan really did change, the live folder stops
    validating and this run falls back to manual review -- the right outcome.

    Files still byte-identical to domains/_template, because export_zone()
    only rewrites a file it has data for and leaves the rest as the template
    copytree() put there. This repo's exporter does not cover every service
    (email routing, certificate packs, total TLS, CT alerting, DNSSEC when
    the API doesn't report it...), and copying the blank template over a
    populated file would quietly stop managing it. Silence from the exporter
    means "no information", never "delete what you have"."""
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

    # The deviation-detection workflow has already run deviation-check by the
    # time it calls this, so deviation.json is usually on disk. Standalone
    # runs need it generated first.
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
        # export_account() writes in place, so there is nothing to withhold;
        # a validation failure here just means nothing gets committed.
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

        # export_zone() already ran the validator (structural checks + the
        # policy.yaml gate) over the staging folder and returned its exit
        # code. Check it *before* copying anything: a re-export that fails the
        # checks a human PR would have to pass must not reach the folder
        # people edit, even uncommitted. (Missing record-doc warnings fire on
        # the staging copy because the blocks go back below; warnings never
        # affect this exit code.)
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

    # Validate the live folder (not just the export) now that the documentation
    # is back and the settings files are restricted.
    validate_export(path)

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
