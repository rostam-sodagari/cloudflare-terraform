'Static compliance audit: scores this repository\'s YAML against the controls\nin docs/Cloudflare_Account_Audit.docx and docs/Cloudflare_Zone_Audit.docx,\nthen writes a Word report.\n\nOnly controls answerable from the files in this repo are graded (Pass /\nPartial / Fail / N/A). Everything else in those two checklists -- identity\nand SSO, live Cloudflare/GitHub API state, origin-side checks, Enterprise\nfeatures this repo has no module for, and pure process evidence -- is\nlisted separately in the report\'s appendix as "needs a live or manual\ncheck", never guessed at.\n\n    python3 scripts/compliance_audit.py                    audit everything -> .audit/audit-report.docx\n    python3 scripts/compliance_audit.py example.com         audit one domain (+ account)\n    python3 scripts/compliance_audit.py --out report.docx\n    python3 scripts/compliance_audit.py --live              also run `cf.py deviation-check` per root (needs credentials)\n\nRequires: pip install python-docx (not in requirements.txt -- only report\ngeneration needs it, not everyday YAML editing).'
import argparse
import subprocess
import sys
from pathlib import Path
from repository_paths import repository_root
from .catalog import STATUSES, STATUS_RGB, NOT_EVALUATED
from .common import Result, load, managed_or, workflow_has_schedule
from .domain import audit_domain, _audit_dns, _audit_tls, _audit_waf, _audit_rate_limits, _audit_bots, _audit_cache, _audit_origin, _audit_logging
from . import account as account_controls
from .report import build_report

ROOT = repository_root(__file__)


def audit_account(a, domain_owners):
    return account_controls.audit_account(a, domain_owners, repository_root=ROOT)


def run_live_deviation_check(root_name):
    proc = subprocess.run([sys.executable, str(ROOT / "cf.py"), "deviation-check", root_name, "--deviation-exit"],
                           cwd=ROOT, capture_output=True, text=True)
    if proc.returncode == 0:
        return "PASS", "`cf.py deviation-check` found no changes outside Git"
    if proc.returncode == 2:
        return "FAIL", "`cf.py deviation-check` found changes outside Git -- see deviation.log"
    return "MANUAL", "`cf.py deviation-check` could not run (likely missing credentials); run it manually"


def main():
    try:
        _run()
    except (ValueError, OSError) as error:
        sys.exit(str(error))


def _run():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("domains", nargs="*", help="domain folders to audit (default: all under domains/)")
    parser.add_argument("--out", default=str(ROOT / ".audit" / "audit-report.docx"),
                    help="default: .audit/audit-report.docx (gitignored)")
    parser.add_argument("--live", action="store_true", help="also run `cf.py deviation-check` per root (needs credentials)")
    cli_args = parser.parse_args()

    try:
        import docx  # noqa: F401
    except ImportError:
        sys.exit("python-docx is required for the report: pip install python-docx")

    names = cli_args.domains or sorted(policy.name for policy in (ROOT / "domains").iterdir() if policy.is_dir() and not policy.name.startswith("_"))

    domain_owners = []
    domain_sections_full = []
    for name in names:
        domain_dir = ROOT / "domains" / name
        if not domain_dir.is_dir():
            sys.exit(f"No such domain folder: {domain_dir}")
        results, dom, is_example = audit_domain(domain_dir)
        if cli_args.live:
            status, evidence = run_live_deviation_check(name)
            for rule in results:
                if rule.id == "LOG-05":
                    rule.status, rule.evidence = status, evidence
        domain_owners.append((name, dom.get("owner")))
        domain_sections_full.append((name, results, is_example))

    account_results = audit_account(ROOT / "account", domain_owners)

    build_report(account_results, domain_sections_full, cli_args.out)
    print(f"Wrote {cli_args.out}")
