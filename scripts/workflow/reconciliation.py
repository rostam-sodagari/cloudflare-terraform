"""State-only resync with explicit checkpoints and retained recovery evidence."""
import json
import os
import subprocess
from pathlib import Path
from .inventory import save
from .semantics import bindings, state_only


def terraform(root, *arguments):
    result = subprocess.run([os.environ.get("TF", "terraform"), f"-chdir={root}", *arguments],
                            capture_output=True, text=True, encoding="utf-8", timeout=1800)
    if result.returncode:
        raise RuntimeError(f"Terraform {arguments[0]} failed; inspect retained reconciliation logs")
    return result.stdout


def read_state(root):
    return json.loads(terraform(root, "show", "-json"))


def state_bindings(root):
    return bindings(read_state(root))


def checkpoint(root, phase, **details):
    path = Path(root) / ".reconciliation.json"
    previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    save(path, {**previous, **details, "phase": phase})


def execute(root, command, filename):
    result = subprocess.run([os.environ.get("TF", "terraform"), f"-chdir={root}", *command],
                            capture_output=True, text=True, encoding="utf-8", timeout=1800)
    with (Path(root) / filename).open('a', encoding='utf-8') as log:
        log.write('\nTerraform ' + ' '.join(command) + '\n' + result.stdout + result.stderr)
    if result.returncode:
        checkpoint(root, "failed", operation=command[0])
        raise RuntimeError(f"State reconciliation failed; inspect {filename}; state may have changed")


def reconcile(root, snapshot=None):
    """Candidate YAML and imports.tf are already installed and validated.

    Refresh-only apply may forget remotely deleted bindings. A normal plan
    with import blocks then must contain only no-op imports, never mutations.
    Terraform verifies state serials and locks each state operation.
    """
    root = Path(root)
    try:
        version = json.loads(terraform(root, "state", "pull"))
    except RuntimeError:
        # An empty backend is valid during first adoption; unreadable state is not.
        if read_state(root).get('values'):
            raise
        version = {}
    checkpoint(root, "refresh-planning", lineage=version.get("lineage"), serial=version.get("serial"))
    execute(root, ["plan", "-refresh-only", "-input=false", "-lock-timeout=60s", "-out=.refresh.bin"], ".refresh.log")
    checkpoint(root, "refresh-applying")
    execute(root, ["apply", "-input=false", "-lock-timeout=60s", ".refresh.bin"], ".refresh.log")
    checkpoint(root, "import-planning")
    execute(root, ["plan", "-input=false", "-lock-timeout=60s", "-out=.reconcile.bin"], ".reconcile.log")
    plan = json.loads(terraform(root, "show", "-json", ".reconcile.bin"))
    save(root / ".reconcile-plan.json", plan)
    # Disabled routing is represented by absence of the settings resource.
    # Forget an already-disabled binding without another Cloudflare disable call.
    disabled = (snapshot or {}).get('observations', {}).get('email-settings', {})
    forget = [change['address'] for change in plan.get('resource_changes', [])
              if change.get('type') == 'cloudflare_email_routing_settings'
              and change['change']['actions'] == ['delete']
              and (change['change'].get('before') or {}).get('zone_id') == (snapshot or {}).get('identity')
              and disabled.get('status') == 'ok' and disabled.get('value', {}).get('enabled') is False]
    if forget:
        checkpoint(root, 'forgetting-disabled-email', addresses=forget)
        execute(root, ['state', 'rm', '-lock-timeout=60s', *forget], '.reconcile.log')
        execute(root, ['plan', '-input=false', '-lock-timeout=60s', '-out=.reconcile.bin'], '.reconcile.log')
        plan = json.loads(terraform(root, 'show', '-json', '.reconcile.bin'))
        save(root / '.reconcile-plan.json', plan)
    if not state_only(plan):
        checkpoint(root, "blocked-live-mutation")
        raise RuntimeError("Export is not lossless: reconciliation would change Cloudflare; nothing from this plan was applied")
    checkpoint(root, "import-applying")
    execute(root, ["apply", "-input=false", "-lock-timeout=60s", ".reconcile.bin"], ".reconcile.log")
    checkpoint(root, "verifying")
    execute(root, ["plan", "-input=false", "-lock-timeout=60s", "-out=.verify.bin"], ".verify.log")
    verify = json.loads(terraform(root, "show", "-json", ".verify.bin"))
    if not state_only(verify) or any(change["change"].get("importing") for change in verify.get("resource_changes", [])):
        checkpoint(root, "not-converged")
        raise RuntimeError("State reconciliation did not converge; automatic publication stopped")
    checkpoint(root, "state-reconciled")
    for filename in (".refresh.bin", ".reconcile.bin", ".verify.bin"):
        (root / filename).unlink(missing_ok=True)
