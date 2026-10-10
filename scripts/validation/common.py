"""Compatibility exports for shared validation helpers.

Implementations live in modules scoped to reporting, checks,
DKIM parsing and provider schemas. Existing script imports remain supported.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import HOST_RE, LIST_REF_RE, REF_RE, REGEX_RE
from yamlio import DuplicateKeyError, line_for, load_with_lines, unquote_txt
from .paths import ROOT
from .reporting import Ctx, Report
from .dkim import _der_tlv, dkim_tags, rsa_key_bits
from .checks import (
    check_enum, check_fields, check_host, check_ref, check_ttl, check_type,
    expression_checks, fmt_path, is_cidr, is_ip, suggest, list_values,
)
from .schema import RULE_SCHEMA, check_rule_schema


def load(report, file):
    try:
        return load_with_lines(file)
    except DuplicateKeyError as e:
        report.add("error", file, e.line, f"duplicate key '{e.key}' (also on line {e.first_line}).",
                   "every key in a file must be unique; rename one of them")
    except Exception as e:  # yaml syntax
        mark = getattr(e, "problem_mark", None)
        report.add("error", file, (mark.line + 1) if mark else 1, f"YAML syntax error: {getattr(e, 'problem', e)}",
                   "check indentation (spaces, not tabs) and that every 'key: value' has a space after the colon")
    return "ERROR", {}
