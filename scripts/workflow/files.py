"""Confine operational paths and restore configuration after failed guards."""
from contextlib import contextmanager
from pathlib import Path
import re

DOMAIN_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
COPY_EXCLUDES = (".git", ".terraform", ".venv", "graphify-out", "__pycache__",
                 ".state", ".export", "backend.hcl", ".env", ".env.*",
                 "plan.bin", "plan.json", "plan.log", "plan-summary.md",
                 ".plan-input.sha256", ".plan-revision", "deviation.*", ".init.log",
                 ".inventory.json", ".review.json", ".provider-schema.json", ".reconciliation.json",
                 ".reconcile*", ".refresh*", ".verify*", ".preflight*", ".operation-lock",
                 '.inventory-before.json', 'inventory-report.md', 'plan-details.md', 'apply.log',
                 'deployment-outcome.json', '.outcome*')


def confined_path(parent, *parts):
    parent = Path(parent).resolve()
    target = parent.joinpath(*parts).resolve()
    if target == parent or not target.is_relative_to(parent):
        raise ValueError(f"Path escapes its intended directory: {target}")
    return target


def resolve_root(repository, name):
    if name == "account":
        return confined_path(repository, "account")
    if not DOMAIN_NAME.fullmatch(name):
        raise ValueError(f"'{name}' is not a valid domain folder name")
    domains_dir = confined_path(repository, "domains")
    return confined_path(domains_dir, name)


def configuration_files(directory):
    for path in Path(directory).rglob("*"):
        if ".terraform" not in path.parts and path.is_file() and (path.suffix in {".yaml", ".yml", ".tf"} or path.name in {".cloudflare-observed.json", ".cloudflare-bindings.json"}):
            if path.is_symlink() or not path.resolve().is_relative_to(Path(directory).resolve()):
                raise ValueError(f"Configuration file escapes its root: {path}")
            yield path


@contextmanager
def configuration_transaction(directory, *, committed=None):
    """Restore YAML/Terraform files if publication or any subsequent guard fails."""
    directory = Path(directory)
    original = {path.relative_to(directory): path.read_bytes() for path in configuration_files(directory)}
    try:
        yield
    except BaseException:
        if committed is not None and committed():
            raise  # keep committed configuration when only the push failed
        for path in configuration_files(directory):
            if path.relative_to(directory) not in original:
                path.unlink()
        for relative, content in original.items():
            target = confined_path(directory, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        raise
