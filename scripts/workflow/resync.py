#!/usr/bin/env python3
"""
Auto-remediation for deviation detection: re-export a deviated root from the
live Cloudflare API and, only if the result passes the same structural and
policy checks as any pull request, commit and push it straight to main.

Bypassing review is deliberate. The guardrails that make that safe, and the
branch protection it needs, are in docs/operations.md#dashboard-changes. If any
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
import tempfile
from pathlib import Path

import yaml

from repository_paths import repository_root
ROOT = repository_root(__file__)
import export_zone  # noqa: E402
from yamlio import dump_with_header, header_of  # noqa: E402
from .files import COPY_EXCLUDES, confined_path, configuration_transaction, resolve_root
from .inventory import collect, require_complete, record, save
from .reconciliation import state_bindings, reconcile, checkpoint
from .locking import operation_lock
from .journal import Journal

# Only adopts objects not yet in state, so a resync removes a stale one.
ALLOWED_DELETIONS = {"imports.tf"}


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def validate_export(path):
    arguments = [str(path)]
    if path.name == "account":
        arguments += ["--account-dir", str(path)]
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate.py"), *arguments],
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
    config_file = Path(root_dir) / "deviation.json"
    if not config_file.exists():
        return None
    try:
        data = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("resource_drift", []), list):
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
    relative_path = rel
    out = []
    for line in git("status", "--porcelain", "--", relative_path).stdout.splitlines():
        if not line.strip():
            continue
        xy, name = line[:2], line[3:].strip().strip('"')
        if "D" in xy and Path(name).name not in ALLOWED_DELETIONS:
            out.append(name)
    return out


def copy_yaml(staging, dest):
    """Copy only the YAML the export actually wrote into the live folder.

    Keep the human-maintained domain identity. A manifest distinguishes an
    authoritative empty API service from an unread/unexported template file;
    only the former may clear previously managed configuration.
    """
    template = ROOT / "domains" / "_template"
    manifest = Path(staging) / ".exported-files.json"
    exported = set(json.loads(manifest.read_text(encoding="utf-8"))) if manifest.exists() else set()
    copied, skipped = 0, []
    for src in sorted(Path(staging).rglob("*.yaml")):
        relative_path = src.relative_to(staging)
        if relative_path.as_posix() == "domain.yaml":
            continue
        tpl = template / relative_path
        if relative_path.as_posix() not in exported and tpl.exists() and src.read_bytes() == tpl.read_bytes():
            skipped.append(relative_path.as_posix())
            continue
        target = confined_path(dest, relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
        copied += 1
    if skipped:
        print(f"  left alone (nothing exported for them): {', '.join(skipped)}")
    return copied


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", help="domain folder name, or 'account'")
    parser.add_argument("--bot-name", default="deviation-bot")
    parser.add_argument("--bot-email", default="deviation-bot@users.noreply.github.com")
    parser.add_argument("--branch", default="main")
    cli_args = parser.parse_args()

    run_resync(cli_args)


def run_resync(a):
    with operation_lock(ROOT):
        try:
            _run_resync(a)
        except BaseException:
            if getattr(a, "_journal_started", False):
                try:
                    a._journal.finish("resync-failed")
                except (RuntimeError, OSError):
                    print("Journal could not be finalized; inspect the interrupted operation before retrying.", file=sys.stderr)
            raise


def _run_resync(a):
    cli_args = a
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        sys.exit("CLOUDFLARE_API_TOKEN is required")
    client = export_zone.Client(token)

    try:
        path = resolve_root(ROOT, cli_args.root)
    except ValueError as error:
        sys.exit(str(error))
    if not path.is_dir():
        sys.exit(f"no such root: {path}")
    relative_path = path.relative_to(ROOT).as_posix()
    _require_clean_worktree(relative_path)
    revision = git('rev-parse', 'HEAD')
    remote = git('ls-remote', 'origin', f'refs/heads/{cli_args.branch}')
    remote_revision = remote.stdout.split()[0] if remote.stdout.split() else None
    if revision.returncode or remote.returncode or revision.stdout.strip() != remote_revision:
        sys.exit('resync must start from the current target branch revision; fetch it into a clean checkout first')
    journal = Journal(cli_args.root)
    journal.start("resync", revision=git("rev-parse", "HEAD").stdout.strip())
    cli_args._journal, cli_args._journal_started = journal, True

    initial_drift = _initial_drift(cli_args.root, path)
    snapshot = collect(client, path)
    require_complete(snapshot)
    cli_args.bindings = state_bindings(path)
    starting_revision = git("rev-parse", "HEAD").stdout.strip()
    checkpoint(path, "staging", revision=starting_revision, snapshot=snapshot["digest"])

    commit_state = []
    state_started = []
    with configuration_transaction(path, committed=lambda: bool(commit_state or state_started)):
        if cli_args.root == "account":
            _resync_account(client, path, cli_args.bindings)
        else:
            _resync_domain(client, cli_args, path)

        _verify_export(path, relative_path)
        verify_drift_unchanged(cli_args.root, path, initial_drift)
        current = collect(client, path)
        require_complete(current)
        if snapshot["digest"] != current["digest"]:
            sys.exit("Cloudflare changed while this resync was running; automatic reconciliation stopped")
        state_started.append(True)
        reconcile(path, snapshot)
        current = collect(client, path)
        require_complete(current)
        if snapshot["digest"] != current["digest"]:
            sys.exit("Cloudflare changed during reconciliation; retain candidate and retry from a fresh snapshot")
        (path / "imports.tf").unlink(missing_ok=True)
        save(path / ".cloudflare-observed.json", record(snapshot))
        save(path / ".cloudflare-bindings.json", state_bindings(path))
        status_result = git("status", "--porcelain", "--", relative_path)
        if status_result.returncode != 0:
            sys.exit("could not read git status; refusing to commit")
        status = status_result.stdout.strip()
        if not status:
            print(f"no change after export; {relative_path} already matches live Cloudflare")
            checkpoint(path, "complete", revision=starting_revision)
            journal.finish("complete", observed=record(snapshot))
            return
        _commit_resync(cli_args, relative_path, status, on_commit=lambda: commit_state.append(True))
        checkpoint(path, "complete", revision=git("rev-parse", "HEAD").stdout.strip())
        journal.finish("complete", observed=record(snapshot))


def _initial_drift(root_name, path):
    # The workflow has already run deviation-check; standalone runs have not.
    initial_drift = drift_fingerprint(path)
    if initial_drift is None:
        result = run_deviation_check(root_name)
        if result.returncode not in (0, 2):
            sys.exit("deviation check failed, falling back to manual review:\n"
                     + result.stdout + result.stderr)
        initial_drift = drift_fingerprint(path)
        if initial_drift is None:
            sys.exit("could not read the deviation report; falling back to manual review")

    return initial_drift


def _resync_account(client, path, bindings=None):
    account_yaml = yaml.safe_load((path / "account.yaml").read_text(encoding="utf-8")) or {}
    with tempfile.TemporaryDirectory(prefix="account-resync-") as workspace:
        candidate = Path(workspace) / "account"
        shutil.copytree(path, candidate, ignore=shutil.ignore_patterns(*COPY_EXCLUDES))
        export_args = argparse.Namespace(account_id=account_yaml.get("account_id"), plan=account_yaml.get("plan"), dest=candidate, bindings=bindings)
        try:
            exit_code = export_zone.export_account(client, export_args)
        except (PermissionError, RuntimeError) as error:
            sys.exit(f"export failed, falling back to manual review: {error}")
        if exit_code != 0:
            sys.exit("re-exported YAML failed validation; falling back to manual review")
        validate_export(candidate)
        copy_yaml(candidate, path)
        shutil.copyfile(candidate / "imports.tf", path / "imports.tf")


def _resync_domain(client, cli_args, path):
    domain_yaml = yaml.safe_load((path / "domain.yaml").read_text(encoding="utf-8")) or {}

    # The staging folder has to be named after the domain: validate.py
    # errors when domain.yaml's `name` doesn't match its folder name.
    # Validate even direct helper calls; check resolved containment before delete.
    resolve_root(ROOT, cli_args.root)
    export_dir = confined_path(ROOT, ".export")
    staging_root = confined_path(export_dir, cli_args.root, "resync")
    if staging_root.exists():
        shutil.rmtree(staging_root)   # our own scratch from an earlier run
    staging_root.mkdir(parents=True, exist_ok=True)
    staging = staging_root / cli_args.root
    export_args = argparse.Namespace(zone_id=domain_yaml.get("zone_id"), domain=cli_args.root,
                            plan=domain_yaml.get("plan"), force=False, dest=staging,
                            bindings=cli_args.bindings)
    scope_file = path / 'security/authenticated-origin-pulls.yaml'
    scope = (yaml.safe_load(scope_file.read_text(encoding='utf-8')) or {}) if scope_file.exists() else {}
    export_args.origin_pull_hostname = scope.get('hostname')
    try:
        exit_code = export_zone.export_zone(client, export_args)
    except (PermissionError, RuntimeError) as e:
        sys.exit(f"export failed, falling back to manual review: {e}")

    # Checked before the copy: a re-export that fails validation must not
    # reach the folder people edit, even uncommitted.
    if exit_code != 0:
        shutil.rmtree(staging_root, ignore_errors=True)
        sys.exit("re-exported YAML failed validation; falling back to manual review")

    # Validate the merged candidate, including retained services and identity.
    with tempfile.TemporaryDirectory(prefix="domain-resync-") as workspace:
        candidate = Path(workspace) / cli_args.root
        shutil.copytree(path, candidate, ignore=shutil.ignore_patterns(*COPY_EXCLUDES))
        copy_yaml(staging, candidate)
        validate_export(candidate)
    copy_yaml(staging, path)
    shutil.copyfile(staging / "imports.tf", path / "imports.tf")
    shutil.rmtree(staging_root, ignore_errors=True)


def _verify_export(path, relative_path):
    gone = deleted_files(relative_path)
    if gone:
        sys.exit("refusing to commit: the re-export would delete " + ", ".join(gone)
                 + ". Falling back to manual review.")

    validate_export(path)



def _commit_resync(a, rel, status, *, on_commit=None):
    cli_args = a
    relative_path = rel
    for arguments in (("config", "user.name", cli_args.bot_name),
                      ("config", "user.email", cli_args.bot_email),
                      ("add", "--", relative_path)):
        result = git(*arguments)
        if result.returncode != 0:
            if arguments[0] == "add":
                git("reset", "--", relative_path)
            sys.exit(f"git {arguments[0]} failed; refusing to commit: {result.stderr}")
    changed_files = "\n".join(line[3:] for line in status.splitlines())
    message = (
        f"Sync {cli_args.root} with live Cloudflare state (deviation detected)\n\n"
        f"Auto-committed by deviation detection: the YAML below was out of date "
        f"with what's actually configured in Cloudflare. The re-exported version "
        f"passed the same structural and policy checks a pull request would need "
        f"to pass and deleted nothing."
        f"\n\nFiles changed:\n{changed_files}\n"
    )
    commit = git("commit", "--only", "-m", message, "--", relative_path)
    if commit.returncode != 0:
        git("reset", "--", relative_path)
        sys.exit(f"commit failed: {commit.stdout}\n{commit.stderr}")
    if on_commit is not None:
        on_commit()
    push = git("push", "origin", f"HEAD:{cli_args.branch}")
    if push.returncode != 0:
        sys.exit(f"push failed (check that {cli_args.bot_name} is allowed to bypass branch "
                 f"protection on {cli_args.branch} -- see docs/operations.md#dashboard-changes): "
                 f"{push.stdout}\n{push.stderr}")
    print(f"committed and pushed: {relative_path} synced to live Cloudflare state")


def _require_clean_worktree(relative_path):
    staged = git("diff", "--cached", "--name-only")
    status = git("status", "--porcelain")
    if staged.returncode != 0 or status.returncode != 0:
        sys.exit("cannot verify the working tree; refusing resync")
    if staged.stdout.strip() or status.stdout.strip():
        sys.exit("resync requires a clean checkout and no staged changes; commit or stash local work first")


if __name__ == "__main__":
    main()
