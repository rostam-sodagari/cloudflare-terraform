#!/usr/bin/env python3
"""
Export a live Cloudflare zone (or the account's lists) into this repo's YAML,
with an imports.tf so the first apply ADOPTS what exists instead of
recreating it. Read-only: this script never changes anything in Cloudflare.

    export CLOUDFLARE_API_TOKEN=<read-only token>
    python3 scripts/export_zone.py --zone-id <id> --domain example.org
    python3 scripts/export_zone.py --account-id <id>

Usually run through `python3 cf.py export`.

What you get
  domains/<domain>/              every service file, each with its documentation
                                 header from domains/_template, plus your data
  domains/<domain>/imports.tf    one import block per adopted object
  .export/<domain>/EXPORT_REPORT.md   what was exported and what needs a look

The goal is a first plan that says "0 to add, 0 to change, 0 to destroy".
Anything that cannot be represented exactly is kept in a raw form (SPF/DMARC
`raw:`, managed WAF `raw_rules:`) so nothing changes in Cloudflare.

Safety
  Refuses to overwrite an existing domain folder unless --force; with --force
  the old folder is copied to .export/<domain>/backup-<time>/ first.
"""
import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from yamlio import dump_with_header, header_of, quote_txt, unquote_txt
except ImportError:
    sys.exit("PyYAML is required: pip install -r requirements.txt")

from exporting.config import (API, RULE_SCHEMA, PERMISSIONS, DNS_FILES,
                           MANAGED_IDS, RULE_FILES, BOT_FIELDS_BY_PLAN, SETTINGS,
                           BENIGN_DROPS, CUSTOM_ACTIONS)
from exporting.client import Client, NotFound
from exporting.converters import (custom_rule_fields, rate_limit_fields, list_item_fields, clean, rel, slug, unique, ttl_fields, build_spf,
                               parse_spf, build_dmarc, parse_dmarc, txt_fields,
                               structured_fields)
from exporting.services import ZoneExport
from exporting.output import prepare_dest, write_imports
from exporting import publish
from exporting.publish import _collect_account_lists, _collect_account_waf, _collect_account_logpush

from repository_paths import repository_root
ROOT = repository_root(__file__)
TEMPLATE = ROOT / "domains" / "_template"


def run_validator(target):
    print("\nChecking the exported YAML ...")
    arguments = [str(target)]
    if Path(target).name == "account" and (Path(target) / "account.yaml").is_file():
        arguments += ["--account-dir", str(target)]
    return subprocess.call([sys.executable, str(ROOT / "scripts" / "validate.py"), *arguments])


def export_zone(client, a):
    return publish.export_zone(client, a, repository_root=ROOT,
                               template_dir=TEMPLATE, validator=run_validator)


def export_account(client, a):
    return publish.export_account(client, a, repository_root=ROOT, validator=run_validator)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zone-id")
    parser.add_argument("--domain")
    parser.add_argument("--account-id", help="export account lists and Bulk Redirects instead of a zone")
    parser.add_argument("--plan", choices=["free", "pro", "business", "enterprise"], help="override the plan read from the API")
    parser.add_argument("--force", action="store_true", help="replace an existing folder (it is backed up first)")
    cli_args = parser.parse_args()

    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        sys.exit("Set CLOUDFLARE_API_TOKEN first (a read-only token is enough).")
    hexid = re.compile(r"^[0-9a-f]{32}$")
    hostre = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
    client = Client(token)
    try:
        if cli_args.account_id:
            if not hexid.match(cli_args.account_id):
                sys.exit("--account-id must be the 32-character Account ID.")
            sys.exit(export_account(client, cli_args))
        if not (cli_args.zone_id and cli_args.domain):
            parser.error("--zone-id and --domain are required (or --account-id)")
        if not hexid.match(cli_args.zone_id):
            sys.exit("--zone-id must be the 32-character Zone ID.")
        if not hostre.match(cli_args.domain):
            sys.exit("--domain must be a valid hostname (letters, digits, hyphens, dots).")
        sys.exit(export_zone(client, cli_args))
    except (PermissionError, RuntimeError) as e:
        sys.exit(f"Export stopped: {e}")


if __name__ == "__main__":
    main()
