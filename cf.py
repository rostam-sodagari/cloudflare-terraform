#!/usr/bin/env python3
"""
Cloudflare Terraform helper. The one entry point for this repository: works
the same on macOS, Linux and Windows wherever Python 3 and Terraform are
installed. Run `python3 cf.py help` for the full list.

Everyday (people who edit YAML):
  python3 cf.py validate example.com        check the YAML; no token needed
  python3 cf.py plan example.com            show exactly what would change in Cloudflare
  python3 cf.py apply example.com           apply the plan you just reviewed (asks you to confirm)
  python3 cf.py deviation-check example.com list changes made outside Git since the last apply

Setting up domains:
  python3 cf.py new example.org --zone-id <id> --plan pro
  python3 cf.py export example.org --zone-id <id> [--force]   copy a live zone into YAML (read-only)
  python3 cf.py export-account --account-id <id> [--plan pro]

Maintainers:
  python3 cf.py test <domain|account> | test-all | unit | validate-all | fmt | lint | domains
  python3 cf.py migrate <domain|account> --to local|r2         move state between backends
  python3 cf.py changed-domains [--all | <git-ref>]            roots to plan since a ref (used by CI)

Use "account" instead of a domain name for account-level lists.
State goes to R2 by default. Pass --backend local, or set CF_BACKEND=local,
to keep it on this machine in .state/. Set TF=tofu (environment variable) to
use OpenTofu instead of Terraform.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

SCRIPTS = Path(__file__).resolve().parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from repository_paths import repository_root
ROOT = repository_root(__file__)
from workflow.locking import operation_lock
from config import PLANS  # noqa: E402
from workflow import backend as workflow_backend
from workflow import integrity as workflow_integrity
from workflow import process as workflow_process
from workflow.parser import build_parser, subcmd, add_backend_arg
from workflow.files import resolve_root
from workflow import terminal
from domain_scaffold import personalize_zone
from yamlio import dump_with_header, header_of
from workflow.testing import fixture_roots

TF = os.environ.get("TF", "terraform")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HOSTRE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


# Same convention as scripts/validate.py: colour only when the destination
# stream is a real terminal, so piped/redirected output (CI logs, log files)
# stays plain.
def _colour(code, text, stream=None):
    return terminal.colour(code, text, stream)


def red(text):
    return _colour(31, text)


def green(text):
    return _colour(32, text)


def yellow(text):
    return _colour(33, text)


def cyan(text):
    return _colour(36, text)


def fail(msg) -> NoReturn:
    print(_colour(31, msg, sys.stderr), file=sys.stderr)
    sys.exit(1)


def run_py(script, args, capture=False):
    return workflow_process.run_py(script, args, capture, scripts_dir=SCRIPTS)


def run_tf(args, capture=False):
    return workflow_process.run_tf(args, capture, executable=TF, fail=fail)


# --------------------------------------------------------------------------
class Rt:
    """One root to operate on: a domain folder, or 'account'."""

    def __init__(self, name):
        self.name = name
        if name == "account":
            self.dir = ROOT / "account"
            self.key = "account.tfstate"
            self.rel = ".."
        else:
            # Ends up in a -chdir= path and an R2 state key.
            if not HOSTRE.match(name):
                fail(f"'{name}' is not a valid domain folder name (letters, digits, hyphens, dots)")
            self.dir = ROOT / "domains" / name
            self.key = f"domains/{name}.tfstate"
            self.rel = "../.."
        if not self.dir.is_dir():
            fail(f"No such folder: {self.dir}")
        try:
            self.dir = resolve_root(ROOT, name)
        except ValueError as error:
            fail(str(error))


def domains():
    return sorted(p.name for p in (ROOT / "domains").iterdir() if p.is_dir() and not p.name.startswith("_"))


def resolve_backend(a):
    cli_args = a
    backend = getattr(cli_args, "backend", None) or os.environ.get("CF_BACKEND", "r2").lower()
    if backend not in ("local", "r2"):
        fail(f"CF_BACKEND must be local or r2, not '{backend}'")
    return backend


# ---- backend / init -------------------------------------------------------
def backend_setup(r, backend):
    root = r
    return workflow_backend.backend_setup(root, backend, ROOT, fail)


def tf_init(r, backend):
    """Never uses -reconfigure: if the backend differs from the one this root
    was last initialised with, Terraform stops and `migrate` is needed instead
    of silently losing track of the existing state."""
    root = r
    extra = backend_setup(root, backend)
    process_result = run_tf([f"-chdir={root.dir}", "init", "-input=false", *extra], capture=True)
    (root.dir / ".init.log").write_text(process_result.stdout + process_result.stderr, encoding="utf-8")
    if process_result.returncode != 0:
        print(process_result.stdout + process_result.stderr)
        print(yellow(f"\nIf Terraform says the backend changed, run: python3 cf.py migrate {root.name} --to {backend}"))
        sys.exit(process_result.returncode)


def forget(r, *names):
    root = r
    for name in names:
        (root.dir / name).unlink(missing_ok=True)


def plan_fingerprint(r, backend):
    root = r
    return workflow_integrity.plan_fingerprint(root, backend, ROOT, plan_input_digests(root))


def plan_input_digests(r):
    root = r
    return workflow_integrity.plan_input_digests(root, ROOT)


def plan_revision():
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "no-git"


def save_plan_fingerprint(r, backend):
    root = r
    inputs = plan_input_digests(root)
    payload = {
        "backend": backend,
        "fingerprint": plan_fingerprint(root, backend),
        "inputs": {p.relative_to(ROOT).as_posix(): digest for p, digest in inputs.items()},
        "artifacts": {name: hashlib.sha256((root.dir / name).read_bytes()).hexdigest()
                      for name in ("plan.bin", "plan.json")},
    }
    (root.dir / ".plan-input.sha256").write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="ascii")
    (root.dir / ".plan-revision").write_text(plan_revision() + "\n", encoding="ascii")


def check_plan_fingerprint(r, backend):
    root = r
    marker = root.dir / ".plan-input.sha256"
    if not marker.exists():
        fail(f"Saved plan has no input fingerprint. Run: python3 cf.py plan {root.name}")
    try:
        saved = json.loads(marker.read_text(encoding="ascii"))
    except (OSError, ValueError):
        fail(f"Saved plan has an invalid input fingerprint. Run: python3 cf.py plan {root.name}")
    if not isinstance(saved, dict) or not isinstance(saved.get("inputs"), dict):
        fail(f"Saved plan has an invalid input fingerprint. Run: python3 cf.py plan {root.name}")
    artifacts = saved.get("artifacts")
    if not isinstance(artifacts, dict):
        fail(f"Saved plan has no artifact digests. Run: python3 cf.py plan {root.name}")
    for name in ("plan.bin", "plan.json"):
        try:
            digest = hashlib.sha256((root.dir / name).read_bytes()).hexdigest()
        except OSError:
            fail(f"Saved plan artifact {name} is missing or unreadable. Run: python3 cf.py plan {root.name}")
        if artifacts.get(name) != digest:
            fail(f"Saved plan artifact {name} changed after planning. Run: python3 cf.py plan {root.name}")
    for name in (".review.json", ".inventory.json"):
        if name in artifacts:
            path = root.dir / name
            if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != artifacts[name]:
                fail(f"Saved review evidence {name} changed after planning; obtain fresh PR review.")
    expected = saved.get("fingerprint")
    actual = plan_fingerprint(root, backend)
    if expected != actual:
        current = {p.relative_to(ROOT).as_posix(): digest for p, digest in plan_input_digests(root).items()}
        changed = sorted(set(saved.get("inputs", {})) | set(current))
        changed = [path for path in changed if saved.get("inputs", {}).get(path) != current.get(path)]
        detail = f" Changed inputs: {', '.join(changed[:5])}." if changed else ""
        fail("Saved plan is stale: Terraform inputs changed after it was created." +
             detail + f" Run: python3 cf.py plan {root.name}")

    # Missing is a failure, same as a missing .plan-input.sha256 above.
    revision = root.dir / ".plan-revision"
    if not revision.exists():
        fail(f"Saved plan has no revision marker. Run: python3 cf.py plan {root.name}")
    if revision.read_text(encoding="ascii").strip() != plan_revision():
        fail("Saved plan was created from a different revision. "
             f"Run: python3 cf.py plan {root.name}")


def validate(r):
    root = r
    target = "account" if root.name == "account" else str(root.dir)
    exit_code = run_py("validate.py", [target]).returncode
    if exit_code != 0:
        sys.exit(exit_code)


SUMMARY_OK = (0, 2)  # like -detailed-exitcode: 0 = no changes, 2 = changes


def summarise(r, extra=(), capture=False):
    root = r
    process_result = run_py("plan_summary.py", [str(root.dir / "plan.json"), "--root", root.name, *extra], capture=capture)
    if process_result.returncode not in SUMMARY_OK:
        if capture:
            print((process_result.stdout or "") + (process_result.stderr or ""))
        fail(f"Could not read the plan for {root.name} (plan_summary.py exited {process_result.returncode}). "
             f"Refusing to continue with a change summary nobody can review.")
    return process_result


def warning_lines(log_text):
    """Mirrors `grep -E "^(Warning|Error):" -A3 | grep -v "dry run"`: surface
    provider warnings/errors even on an otherwise successful plan."""
    lines = log_text.splitlines()
    picked = set()
    for index, line in enumerate(lines):
        if re.match(r"^(Warning|Error):", line):
            picked.update(range(index, min(index + 4, len(lines))))
    return [lines[index] for index in sorted(picked) if "dry run" not in lines[index]]


# ---- commands --------------------------------------------------------------
def cmd_validate(a):
    cli_args = a
    target = "account" if cli_args.domain == "account" else str(Rt(cli_args.domain).dir)
    sys.exit(run_py("validate.py", [target]).returncode)


def cmd_validate_all(a):
    cli_args = a
    sys.exit(run_py("validate.py", ["--all"]).returncode)


def cmd_init(a):
    cli_args = a
    tf_init(Rt(cli_args.domain), resolve_backend(cli_args))


def cmd_plan(a):
    cli_args = a
    root = Rt(cli_args.domain)
    backend = resolve_backend(cli_args)
    terminal.step("Validate configuration")
    validate(root)
    terminal.step(f"Initialize {backend} state")
    tf_init(root, backend)
    # Clear the fingerprint too: a leftover one would let `apply` pair this
    # run's plan.bin with the previous run's summary.
    forget(root, "plan.bin", "plan.json", ".plan-input.sha256", ".plan-revision")
    print(f"Planning {root.name} (reads Cloudflare, changes nothing) ...")
    process_result = run_tf([f"-chdir={root.dir}", "plan", "-input=false", "-lock-timeout=60s", "-out=plan.bin"], capture=True)
    log = process_result.stdout + process_result.stderr
    (root.dir / "plan.log").write_text(log, encoding="utf-8")
    if process_result.returncode != 0:
        print(log)
        sys.exit(process_result.returncode)
    for line in warning_lines(log):
        print(red(line) if line.startswith("Error:") else yellow(line) if line.startswith("Warning:") else line)
    show = run_tf([f"-chdir={root.dir}", "show", "-json", "plan.bin"], capture=True)
    if show.returncode != 0:
        print(show.stdout + show.stderr)
        fail(f"'terraform show' could not read the saved plan for {root.name}. "
             f"No change summary was written, so nothing can be applied from it.")
    (root.dir / "plan.json").write_text(show.stdout, encoding="utf-8")
    terminal.step("Build the change summary")
    md = summarise(root, ["--format", "md"], capture=True)
    (root.dir / "plan-summary.md").write_text(md.stdout, encoding="utf-8")
    summarise(root)
    save_plan_fingerprint(root, backend)
    print()
    if terminal.interactive():
        print(terminal.colour("1", "Saved reports"))
        print(f"  Terraform log: {root.dir / 'plan.log'}")
        print(f"  PR summary:    {root.dir / 'plan-summary.md'}")
        print(f"\nNext: python3 cf.py apply {root.name}")
    else:
        print(f"Full Terraform output: {root.dir}/plan.log   Summary for the PR: {root.dir}/plan-summary.md")


def cmd_apply(a):
    cli_args = a
    root = Rt(cli_args.domain)
    # Re-validate here, not just at plan time: policy.yaml (or the YAML
    # itself) may have changed since this plan was saved, and a stale
    # plan.bin would otherwise apply against a policy it no longer meets.
    backend = resolve_backend(cli_args)
    marker = root.dir / ".plan-input.sha256"
    if getattr(cli_args, "backend", None) is None and "CF_BACKEND" not in os.environ and marker.exists():
        try:
            saved_backend = json.loads(marker.read_text(encoding="ascii")).get("backend")
            if saved_backend in ("local", "r2"):
                backend = saved_backend
        except (OSError, ValueError, AttributeError):
            pass
    terminal.step("Validate configuration and saved plan integrity")
    validate(root)
    check_plan_fingerprint(root, backend)
    if not (root.dir / "plan.bin").exists():
        fail(f"No saved plan. Run: python3 cf.py plan {root.name}")
    verify_plan_json(root)
    if backend == 'r2' and os.environ.get('GITHUB_ACTIONS') != 'true':
        fail('Shared R2 deployments require the reviewed PR workflow. Use a local backend for sandbox applies.')
    if os.environ.get("CI"):
        from ci_review import preflight
        preflight(root.dir)
        from workflow.journal import Journal
        journal = Journal(root.name)
        evidence = json.loads((root.dir / ".review.json").read_text(encoding="utf-8"))
        journal.start("apply", revision=plan_revision(), reviewed_at=evidence["created"])
    terminal.step("Review changes")
    summarise(root)
    yes = cli_args.yes or os.environ.get("YES") == "1"
    if not os.environ.get("CI") and not yes:
        answer = input(f"\nType the name '{root.name}' to apply exactly these changes: ")
        if answer != root.name:
            fail("Cancelled. Nothing was changed.")
    terminal.step("Apply the reviewed plan")
    process_result = run_tf([f"-chdir={root.dir}", "apply", "-input=false", "plan.bin"])
    if process_result.returncode != 0:
        if os.environ.get("CI"):
            journal.finish("apply-failed")
        print(red("Apply failed and may have made partial changes. Inspect Cloudflare and state before recovery."))
        sys.exit(process_result.returncode)
    forget(root, "plan.bin", "plan.json")
    print(green(f"Applied. Run 'python3 cf.py plan {root.name}': it should now say 'Nothing will change'."))


def verify_plan_json(root):
    """Require the reviewed JSON to describe the binary Terraform will apply."""
    result = run_tf([f"-chdir={root.dir}", "show", "-json", "plan.bin"], capture=True)
    try:
        actual = json.loads(result.stdout) if result.returncode == 0 else None
        reviewed = json.loads((root.dir / "plan.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        fail("Cannot verify the saved plan; run plan again before applying.")
    if not isinstance(actual, dict) or actual != reviewed:
        fail("Saved plan binary does not match the reviewed JSON; run plan again before applying.")


def cmd_deviation_check(a):
    cli_args = a
    root = Rt(cli_args.domain)
    tf_init(root, resolve_backend(cli_args))
    process_result = run_tf([f"-chdir={root.dir}", "plan", "-refresh-only", "-input=false",
                   "-lock-timeout=60s", "-out=deviation.bin"], capture=True)
    (root.dir / "deviation.log").write_text(process_result.stdout + process_result.stderr, encoding="utf-8")
    if process_result.returncode != 0:
        print(process_result.stdout + process_result.stderr)
        sys.exit(process_result.returncode)
    show = run_tf([f"-chdir={root.dir}", "show", "-json", "deviation.bin"], capture=True)
    if show.returncode != 0:
        print(show.stdout + show.stderr)
        fail(f"'terraform show' could not read the saved deviation plan for {root.name}. "
             "No deviation report was written.")
    (root.dir / "deviation.json").write_text(show.stdout, encoding="utf-8")
    forget(root, "deviation.bin")
    exit_code = run_py("plan_summary.py", [str(root.dir / "deviation.json"), "--root", root.name, "--deviation-only"]).returncode
    if cli_args.deviation_exit:
        sys.exit(exit_code)


def cmd_migrate(a):
    cli_args = a
    root = Rt(cli_args.domain)
    if not cli_args.to:
        fail("python3 cf.py migrate <domain|account> --to local|r2")
    extra = backend_setup(root, cli_args.to)
    # Interactive on purpose: Terraform asks before copying state.
    process_result = run_tf([f"-chdir={root.dir}", "init", "-migrate-state", *extra])
    if process_result.returncode != 0:
        sys.exit(process_result.returncode)
    print(green(f"Done. Run: python3 cf.py plan {root.name} --backend {cli_args.to}   (expect No changes)"))


def test_one(r):
    """imports.tf is set aside: mocked providers cannot import, and import
    blocks only matter for a real plan."""
    root = r
    validate(root)
    imports, parked = root.dir / "imports.tf", root.dir / ".imports.tf.skip"
    moved = imports.exists()
    if moved:
        imports.rename(parked)
    try:
        process_result = run_tf([f"-chdir={root.dir}", "init", "-backend=false", "-input=false"], capture=True)
        if process_result.returncode != 0:
            print(process_result.stdout + process_result.stderr)
            raise SystemExit(process_result.returncode)
        if run_tf([f"-chdir={root.dir}", "test"]).returncode != 0:
            raise SystemExit(1)
    finally:
        if moved:
            parked.rename(imports)


def cmd_test(a):
    cli_args = a
    test_one(Rt(cli_args.domain))


def cmd_test_all(a):
    cli_args = a
    failed = []
    for name in ["account"] + domains():
        print(cyan(f"== {name}"))
        try:
            test_one(Rt(name))
        except SystemExit:
            failed.append(name)
    with fixture_roots(ROOT) as roots:
        for root in roots:
            print(cyan(f"== fixture/{root.name}"))
            try:
                test_one(root)
            except SystemExit:
                failed.append(f"fixture/{root.name}")
    for directory in sorted((ROOT / "modules").glob("*/tests")):
        module_dir = directory.parent
        print(cyan(f"== modules/{module_dir.name}"))
        result = run_tf([f"-chdir={module_dir}", "init", "-backend=false", "-input=false"], capture=True)
        if result.returncode != 0:
            print(result.stdout + result.stderr)
            failed.append(f"modules/{module_dir.name}")
        elif run_tf([f"-chdir={module_dir}", "test"]).returncode != 0:
            failed.append(f"modules/{module_dir.name}")
    if failed:
        fail(f"Failed: {', '.join(failed)}")


def cmd_unit(a):
    cli_args = a
    sys.exit(subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]).returncode)


def cmd_fmt(a):
    cli_args = a
    sys.exit(run_tf([f"-chdir={ROOT}", "fmt", "-recursive"]).returncode)


def cmd_lint(a):
    cli_args = a
    exit_code = run_tf([f"-chdir={ROOT}", "fmt", "-recursive", "-check"]).returncode
    if exit_code != 0:
        sys.exit(exit_code)
    sys.exit(run_py("validate.py", ["--all"]).returncode)


def cmd_domains(a):
    cli_args = a
    for d in domains():
        print(d)


def cmd_new(a):
    cli_args = a
    if not HOSTRE.match(cli_args.domain):
        fail("domain name must be a valid hostname (letters, digits, hyphens, dots)")
    if not HEX32.match(cli_args.zone_id):
        fail("zone id must be 32 hex characters")
    dest = ROOT / "domains" / cli_args.domain
    if dest.exists():
        fail(f"{dest} already exists")
    shutil.copytree(ROOT / "domains" / "_template", dest)
    identity_file = dest / "domain.yaml"
    dump_with_header(identity_file, {
        "name": cli_args.domain, "zone_id": cli_args.zone_id,
        "plan": cli_args.plan, "owner": "change-me",
    }, header_of(identity_file))
    personalize_zone(dest, cli_args.domain)
    print(green(f"Created {dest}. Fill in the YAML files, then: python3 cf.py plan {cli_args.domain}"))
    print(f"Setup and deployment instructions: {dest / 'README.md'}")


def cmd_export(a):
    cli_args = a
    args = ["--zone-id", cli_args.zone_id, "--domain", cli_args.domain]
    if cli_args.force:
        args.append("--force")
    if cli_args.plan:
        args += ["--plan", cli_args.plan]
    sys.exit(run_py("export_zone.py", args).returncode)


def cmd_export_account(a):
    cli_args = a
    args = ["--account-id", cli_args.account_id]
    if cli_args.plan:
        args += ["--plan", cli_args.plan]
    sys.exit(run_py("export_zone.py", args).returncode)


# ---- roots to plan since a git ref (used by CI) ---------------------------
def _is_example(path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return re.search(r"^example:\s*true", text, re.MULTILINE) is not None


def all_roots():
    out = []
    if not _is_example(ROOT / "account" / "account.yaml"):
        out.append("account")
    out += [d for d in domains() if not _is_example(ROOT / "domains" / d / "domain.yaml")]
    return out


def _git_diff(*args):
    return subprocess.run(["git", "diff", "--name-only", *args], cwd=ROOT,
                          capture_output=True, text=True).stdout


def changed_roots(base, want_all):
    if want_all:
        return all_roots()
    changed = _git_diff(f"{base or 'origin/main'}...HEAD") or _git_diff("HEAD~1", "HEAD")
    lines = [line for line in changed.splitlines() if line]
    if not lines or any(re.match(r"^(modules|scripts)/", line) or
                         line in {"cf.py", "requirements.txt", "policy.yaml", "backend.hcl", "backend.hcl.example"} for line in lines):
        return all_roots()  # shared code changed, or history unavailable: plan everything
    wanted = {"account"} if any(line.startswith("account/") for line in lines) else set()
    for line in lines:
        m = re.match(r"^domains/([^/]+)", line)
        if m:
            wanted.add(m.group(1))
    return [root for root in all_roots() if root in wanted]


def cmd_changed_domains(a):
    cli_args = a
    print(json.dumps(changed_roots(cli_args.base, cli_args.all)))


# ---- CLI wiring -------------------------------------------------------------






def main():
    parser = build_parser(globals(), __doc__)
    cli_args = parser.parse_args()
    if not cli_args.command or cli_args.command == "help":
        parser.print_help()
        return
    if cli_args.command not in ("domains", "changed-domains"):
        terminal.heading(cli_args.command, getattr(cli_args, "domain", None))
    if cli_args.command in ("plan", "apply", "migrate"):
        with operation_lock(ROOT):
            cli_args.fn(cli_args)
    else:
        cli_args.fn(cli_args)


if __name__ == "__main__":
    main()
