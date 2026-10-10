"""Evaluate account governance and shared-service controls."""
import re
from pathlib import Path
from repository_paths import repository_root
from .common import Result, load, workflow_has_schedule

ROOT = repository_root(__file__)


def audit_account(a: Path, domain_owners, *, repository_root=ROOT):
    account_dir = a
    results = []

    def add(cid, area, control, sev, scope, status, evidence):
        results.append(Result(cid, area, control, sev, scope, status, evidence))

    _audit_account_lists(account_dir, domain_owners, add)
    _audit_account_waf(account_dir, domain_owners, add)
    _audit_account_logging(account_dir, domain_owners, add)
    _audit_account_notifications(account_dir, domain_owners, add)
    _audit_account_repository(account_dir, domain_owners, add, repository_root)
    _audit_account_owners(account_dir, domain_owners, add)
    return results


def _audit_account_lists(account_dir, domain_owners, add):
    lists_dir = account_dir / "lists"
    undocumented_lists = []
    total_lists = 0
    for kind in ("ip", "asn", "hostname", "redirect"):
        data = load(lists_dir / f"{kind}.yaml") or {}
        for list_name, list_config in data.items():
            total_lists += 1
            if not isinstance(list_config, dict) or not str(list_config.get("description", "")).strip():
                undocumented_lists.append(f"{kind}.yaml:{list_name}")
    add("ACC-20", "Governance and change management", "Shared IP/ASN/hostname/redirect lists have owners/descriptions", "Low", "All",
        "N/A" if total_lists == 0 else ("PASS" if not undocumented_lists else "PARTIAL"),
        "no lists defined" if total_lists == 0
        else (f"{len(undocumented_lists)} list(s) missing a description: {', '.join(undocumented_lists)}" if undocumented_lists
              else f"all {total_lists} list(s) have descriptions (stale-entry review is still manual)"))

    add("ACC-22", "Governance and change management", "Configuration managed as code", "High", "All", "PARTIAL",
        "repository contains Terraform/YAML for the declared roots; completeness against live Cloudflare objects needs a live inventory comparison")


def _audit_account_waf(account_dir, domain_owners, add):
    custom = load(account_dir / "waf" / "custom-rules.yaml") or []
    add("ACC-18", "Governance and change management", "Account-level custom rulesets", "Medium", "Ent",
        "PASS" if custom else "N/A",
        f"{len(custom)} rule(s) in account/waf/custom-rules.yaml" if custom
        else "account/waf/custom-rules.yaml is empty -- fine if no account-wide custom rules are needed")

    rate_limits = load(account_dir / "waf" / "rate-limits.yaml") or []
    add("ACC-19", "Governance and change management", "Account-level rate limiting rulesets", "Low", "Ent",
        "PASS" if rate_limits else "N/A",
        f"{len(rate_limits)} rule(s) in account/waf/rate-limits.yaml" if rate_limits
        else "account/waf/rate-limits.yaml is empty -- fine if no account-wide rate limits are needed")

    managed = load(account_dir / "waf" / "managed-rules.yaml") or {}
    managed_active = bool(managed.get("raw_rules")) or bool((managed.get("cloudflare_managed") or {}).get("enabled")) \
        or bool((managed.get("owasp") or {}).get("enabled"))
    add("ACC-17", "Governance and change management", "Account-level managed rulesets", "High", "Ent",
        "PASS" if managed_active else "N/A",
        "account/waf/managed-rules.yaml deploys a managed ruleset account-wide" if managed_active
        else "account/waf/managed-rules.yaml is empty -- baseline managed-ruleset protection relies on each zone's own waf/managed-rules.yaml instead")


def _audit_account_logging(account_dir, domain_owners, add):
    logpush = load(account_dir / "settings" / "logpush.yaml") or {}
    audit_log_job = any(j.get("dataset") == "audit_logs" for j in logpush.values() if isinstance(j, dict))
    add("ACC-21", "Governance and change management", "Logpush for account datasets", "High", "Ent",
        "PASS" if audit_log_job else ("PARTIAL" if logpush else "FAIL"),
        "an audit_logs Logpush job is configured" if audit_log_job
        else (f"{len(logpush)} Logpush job(s) configured, but none for the audit_logs dataset" if logpush
              else "account/settings/logpush.yaml has no jobs configured"))


def _audit_account_notifications(account_dir, domain_owners, add):
    notifications = load(account_dir / "settings" / "notifications.yaml") or {}
    enabled_policies = [policy for policy in notifications.values() if isinstance(policy, dict) and policy.get("enabled", True)]
    add("ACC-14", "Governance and change management", "Alerts on sensitive account events", "Medium", "All",
        "PASS" if enabled_policies else "FAIL",
        f"{len(enabled_policies)} enabled notification polic(ies) in account/settings/notifications.yaml" if enabled_policies
        else "no enabled policies in account/settings/notifications.yaml")
    ddos_policies = [policy for policy in enabled_policies if "dos_attack" in str(policy.get("alert_type", "")) or "ddos" in str(policy.get("alert_type", "")).lower()]
    add("ACC-15", "Governance and change management", "DDoS and security notifications", "High", "All",
        "PASS" if ddos_policies else "FAIL",
        f"{len(ddos_policies)} DDoS-related polic(ies) found" if ddos_policies
        else "no policy in account/settings/notifications.yaml has a DDoS-related alert_type")


def _audit_account_repository(account_dir, domain_owners, add, repository_root):
    codeowners = (repository_root / ".github" / "CODEOWNERS").exists()
    add("ACC-23", "Governance and change management", "Peer review enforced for changes", "High", "All",
        "PARTIAL" if codeowners else "FAIL",
        ".github/CODEOWNERS present -- actual required-reviewer/branch-protection settings live in GitHub and are not visible from repo files" if codeowners
        else "no .github/CODEOWNERS; review routing cannot be enforced by code owners alone")

    backend_example = (repository_root / "backend.hcl.example")
    text = backend_example.read_text(encoding="utf-8") if backend_example.exists() else ""
    has_lock = bool(re.search(r"use_lockfile\s*=\s*true", text))
    add("ACC-24", "Governance and change management", "State backend locking configured", "High", "All",
        "PASS" if has_lock else "FAIL",
        "backend.hcl.example sets use_lockfile = true (locking enabled)" if has_lock
        else "backend.hcl.example does not set use_lockfile = true"
        + " -- bucket encryption and access restrictions live in R2 and are not visible from this repo")

    deviation_wf = repository_root / ".github" / "workflows" / "deviation-detection.yml"
    has_schedule = workflow_has_schedule(deviation_wf)
    add("ACC-25", "Governance and change management", "Scheduled deviation detection configured", "Medium", "All",
        "PASS" if has_schedule else "FAIL",
        ".github/workflows/deviation-detection.yml contains a non-empty YAML on.schedule" if has_schedule
        else "no non-empty YAML on.schedule found in the deviation-detection workflow")


def _audit_account_owners(account_dir, domain_owners, add):
    bad_owners = [domain_name for domain_name, owner in domain_owners if not owner or owner == "change-me"]
    add("ACC-27", "Governance and change management", "Zone inventory complete (owners set)", "Medium", "All",
        "N/A" if not domain_owners else ("PASS" if not bad_owners else "FAIL"),
        "no domain folders found" if not domain_owners
        else (f"no real owner set: {', '.join(bad_owners)}" if bad_owners
              else f"all {len(domain_owners)} domain folder(s) have an owner")
        + " -- this only checks folders already in the repo; comparing against Cloudflare's live zone list needs the API and is not done here")
