"""Audit result model and audit-specific YAML semantics."""
from pathlib import Path
import yaml
from yamlio import load_with_lines, DuplicateKeyError


def load(path):
    policy = Path(path)
    if not policy.exists():
        return None
    try:
        return load_with_lines(policy)[0]
    except (yaml.YAMLError, DuplicateKeyError) as error:
        raise ValueError(f"Invalid audit YAML in {policy}: {error}") from error


def workflow_has_schedule(path):
    """Return true only when YAML contains an actual non-empty schedule."""
    data = load(path)
    trigger = data.get("on", data.get(True)) if isinstance(data, dict) else None
    schedule = trigger.get("schedule") if isinstance(trigger, dict) else None
    return isinstance(schedule, list) and bool(schedule)


class Result:
    def __init__(self, cid, area, control, severity, plan_scope, status, evidence):
        self.id, self.area, self.control = cid, area, control
        self.severity, self.plan_scope = severity, plan_scope
        self.status, self.evidence = status, evidence


def managed_or(value, present_ok, present_bad_msg):
    """Shared pattern: an optional zone.yaml-style setting that this repo may
    legitimately leave unset (Cloudflare's default then applies, unmanaged)."""
    if value is None:
        return "MANUAL", "not set in settings/zone.yaml -- this repo leaves it to Cloudflare's default; verify independently"
    if present_ok(value):
        return "PASS", f"settings/zone.yaml: {value!r}"
    return "FAIL", present_bad_msg(value)
