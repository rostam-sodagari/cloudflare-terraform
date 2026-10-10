#!/usr/bin/env python3
"""
Check the YAML in a domain folder (or account/) before Terraform sees it.

    python3 scripts/validate.py domains/example.com
    python3 scripts/validate.py account
    python3 scripts/validate.py --all

Every problem is reported with file, line, what is wrong and how to fix it.
Inside GitHub Actions the same messages appear as annotations on the PR.
Exit code 1 means at least one error; warnings never fail.

What it checks
  1. YAML syntax and duplicate keys (YAML silently keeps the last one).
  2. Unknown fields, with "did you mean" suggestions for typos.
  3. Types and allowed values, including the on/off and number-as-ID traps.
  4. IPs, CIDRs, hostnames, TTLs, ports, priorities, e-mail addresses.
  5. Plan limits and plan-only features, per Cloudflare's documentation.
  6. Cross-file rules: CNAME conflicts, duplicate records, SPF in txt.yaml,
     $list references that do not exist in account/lists.
  7. Rule action_parameters against the provider schema
     (scripts/data/ruleset_rule_schema.json).
"""
import argparse
import sys
from pathlib import Path

from .account import validate_account
from .common import ROOT, Report
from .domain import domain_dirs, validate_domain


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="domain folders or 'account' (default: everything)")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--account-dir", type=Path, default=ROOT / "account", help="account configuration to validate (also supplies list references)")
    a = ap.parse_args()

    report = Report()
    account_dir = a.account_dir.resolve()
    list_names = validate_account(report, account_dir) if account_dir.exists() else None

    targets = a.targets if a.targets and not a.all else ["account"] + [str(p) for p in domain_dirs()]
    for t in targets:
        p = Path(t)
        if t == "account" or p.resolve() == account_dir.resolve():
            continue  # always validated above
        if not p.is_absolute():
            p = (Path.cwd() / p) if (Path.cwd() / p).exists() else ROOT / "domains" / t
        if not p.exists():
            report.add("error", t, 1, f"no such domain folder: {t}")
            continue
        validate_domain(report, p.resolve(), list_names)

    report.print()
    n_err, n_warn = len(report.errors), len(report.items) - len(report.errors)
    if n_err:
        print(f"\n{n_err} error(s), {n_warn} warning(s). Nothing was sent to Cloudflare; fix the errors and run again.")
        sys.exit(1)
    print(f"YAML OK ({n_warn} warning(s)).")


if __name__ == "__main__":
    main()
