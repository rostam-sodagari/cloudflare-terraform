"""Regex patterns shared across validation/*.py."""
import re

HOST_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")
NAME_RE = re.compile(r"^(@|\*|(\*\.)?[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?)$")
KEY_RE = re.compile(r"^[A-Za-z0-9_@.\-]+$")
REF_RE = re.compile(r"^[A-Za-z0-9_\-]{1,120}$")
EMAIL_RE = re.compile(r"^(mailto:)?[^@\s]+@[^@\s]+\.[^@\s]+$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")

REGEX_RE = re.compile(r"(\bmatches\b|\s~\s|\bregex_replace\s*\()")
LIST_REF_RE = re.compile(r"\$([a-z0-9_]+)")

DOC_BLOCK_RE = re.compile(r"^##\s*([A-Za-z]+)\s*:\s*\S")
