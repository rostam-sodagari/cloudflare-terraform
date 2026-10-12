"""Keep local recovery evidence before and after every apply."""
import datetime
import json
import shutil
import uuid
from pathlib import Path


def start(repository, root, run_tf, plan):
    if (root.dir / "errored.tfstate").exists():
        raise RuntimeError("errored.tfstate exists from a failed state save. Recover it before another apply; do not overwrite it.")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = repository / ".state" / "recovery" / root.name / (stamp + "-" + uuid.uuid4().hex[:8])
    directory.mkdir(parents=True, mode=0o700)
    from .semantics import resources
    prior = plan.get("prior_state", {}).get("values", {})
    # Terraform includes objects read for pending imports in prior_state even
    # before they exist in the backend. They do not require an existing backup.
    imports = {item["address"] for item in plan.get("resource_changes", [])
               if item.get("change", {}).get("importing")}
    empty = not any(item.get("mode") != "data" and item.get("address") not in imports
                    for item in resources(prior.get("root_module", {})))
    save_state(root, directory / "before.tfstate", run_tf, allow_empty=empty)
    shutil.copy2(root.dir / "plan.json", directory / "plan.json")
    return directory


def save_state(root, destination, run_tf, allow_empty=False):
    result = run_tf([f"-chdir={root.dir}", "state", "pull"], capture=True)
    if result.returncode:
        if allow_empty and "No state file" in result.stderr:
            return
        raise RuntimeError("Cannot back up Terraform state. Inspect the backend before applying.")
    if not result.stdout.strip() and allow_empty:
        return  # Terraform 1.16 exits successfully with no output for new local state.
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or "lineage" not in value or "serial" not in value:
        raise RuntimeError("Terraform returned invalid state; apply stopped")
    destination.write_text(result.stdout, encoding="utf-8")
    destination.chmod(0o600)


def finish(root, directory, run_tf):
    """Copy the fallback first: the backend may still be unavailable."""
    fallback = root.dir / "errored.tfstate"
    if fallback.exists():
        shutil.copy2(fallback, directory / "errored.tfstate")
        (directory / "errored.tfstate").chmod(0o600)
    try:
        save_state(root, directory / "after.tfstate", run_tf)
    except (RuntimeError, ValueError, OSError) as error:
        (directory / "state-read-error.txt").write_text(str(error), encoding="utf-8")
