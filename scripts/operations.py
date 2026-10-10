"""Configuration inventory reports and checkpoints used by CI and resync."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from exporting.client import Client
from workflow.inventory import collect, differences, record, require_complete, save, redact, unresolved
from workflow.reconciliation import state_bindings
from workflow.files import resolve_root
from repository_paths import ROOT
from workflow.journal import Journal


def detect(root):
    process = subprocess.run([sys.executable, str(ROOT / "cf.py"), "deviation-check", root.name,
                              "--deviation-exit"], cwd=ROOT)
    if process.returncode not in (0, 2):
        raise RuntimeError("Terraform deviation observation failed")
    snapshot = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
    save(root / ".inventory.json", snapshot)
    baseline_file = root / ".cloudflare-observed.json"
    baseline = json.loads(baseline_file.read_text(encoding="utf-8")) if baseline_file.exists() else None
    journal, _ = Journal(root.name).read()
    baseline = journal.get("observed", baseline)
    changed = differences(snapshot, baseline)
    lines = [f"## Configuration inventory: {root.name}", "", "Coverage is limited to the endpoints listed below; logs and other products are not inferred to be covered.", ""]
    for name, observation in snapshot["observations"].items():
        marker = "changed" if name in changed else "unchanged"
        support = "exportable" if observation["exportable"] else "observation only; not automatically mirrored"
        lines.append(f"- {name}: {observation['status']}; {support}; {marker}")
    if changed:
        lines.extend(["", "### Current configuration for changed services", "", "```json",
                      json.dumps(redact({name: snapshot["observations"][name] for name in changed}),
                                 ensure_ascii=False, indent=2), "```"])
    lines.extend(["", *snapshot["problems"]])
    lines.extend(['', *snapshot.get('gaps', [])])
    lines.extend(['', *snapshot.get('limitations', [])])
    if journal.get("phase", "complete") != "complete":
        lines.extend(["", f"An unfinished operation is recorded: {journal['phase']}. Review recovery evidence; resync must not overwrite an incomplete deployment."])
    (root / "inventory-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    require_complete(snapshot)
    if journal.get('phase', 'complete') != 'complete':
        return 3
    supported = [name for name in changed if snapshot['observations'].get(name, {}).get('exportable')]
    if supported or process.returncode == 2:
        return 2
    return 3 if changed or snapshot.get('gaps') else 0


def record_deployment(roots):
    for name in roots:
        root = resolve_root(ROOT, name)
        snapshot = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
        require_complete(snapshot)
        save(root / ".cloudflare-observed.json", record(snapshot))
        save(root / ".cloudflare-bindings.json", state_bindings(root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["detect", "record", 'status', 'verify-storage'])
    parser.add_argument("roots", nargs="+")
    args = parser.parse_args()
    if args.command == 'verify-storage':
        for name in args.roots:
            resolve_root(ROOT, name)
            Journal(name).verify_conditions()
            print(f'{name}: conditional R2 writes verified; temporary probe removed')
        return 0
    if args.command == 'status':
        for name in args.roots:
            resolve_root(ROOT, name)
            value, _ = Journal(name).read()
            print(json.dumps({'root': name, **value}, indent=2))
        return 0
    if args.command == "detect":
        return detect(resolve_root(ROOT, args.roots[0]))
    record_deployment(args.roots)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
