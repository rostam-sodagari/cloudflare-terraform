"""
Carry '##' record documentation blocks across a re-export.

export_zone.py rebuilds a domain's YAML from a data dict, and yaml.safe_dump
cannot keep comments -- so a plain re-export silently drops the
'## Owner/Purpose/Impact(/Proxy)' blocks people write above each DNS record
(docs/41-record-documentation.md). harvest() reads those blocks off the folder
people edit; reinject() puts them back on a freshly exported copy, matched by
record key. lost() compares the two so a caller can refuse to commit an export
that dropped documentation.

Used by scripts/deviation_autofix.py. The scanning rule here is deliberately
the same one validation uses in check_record_doc_blocks(): walk up from a
top-level key's own line while the lines above it match DOC_BLOCK_RE.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from yamlio import load_with_lines  # noqa: E402
from validation.common import DOC_BLOCK_RE, top_level_key_lines  # noqa: E402

# kind (from the filename) -> needs a "Proxy" line too. The single source of
# truth for which files carry record docs; scripts/backfill_record_docs.py
# imports this rather than keeping its own copy.
DNS_FILES = {
    "a": True, "aaaa": True, "cname": True, "mx": False, "txt": False, "ns": False,
    "spf": False, "dmarc": False, "dkim": False, "caa": False, "srv": False,
}


def _keyed_lines(f):
    """(data keys in file order, their 0-based key-line indices, raw lines)."""
    data, _ = load_with_lines(f)
    if not isinstance(data, dict) or not data:
        return [], [], []
    raw = f.read_text(encoding="utf-8").splitlines()
    return list(data), top_level_key_lines(raw), raw


def _block_above(raw, key_idx):
    """The contiguous run of '##' lines directly above a key, in file order."""
    block, i = [], key_idx - 1
    while i >= 0 and DOC_BLOCK_RE.match(raw[i]):
        block.insert(0, raw[i])
        i -= 1
    return block


def _harvest_file(f):
    """{record_key: ['## Owner: ...', ...]} for the documented records in one file."""
    keys, key_lines, raw = _keyed_lines(f)
    out = {}
    for key, key_idx in zip(keys, key_lines):
        block = _block_above(raw, key_idx)
        if block:
            out[key] = block
    return out


def harvest(domain_dir):
    """{'dns/a.yaml': {'www': ['## Owner: ...', ...]}} for every documented record."""
    out = {}
    for kind in DNS_FILES:
        f = Path(domain_dir) / "dns" / f"{kind}.yaml"
        if not f.exists():
            continue
        blocks = _harvest_file(f)
        if blocks:
            out[f"dns/{kind}.yaml"] = blocks
    return out


def reinject(domain_dir, harvested):
    """Put harvested blocks back, matched by record key. Records that are new
    (added in Cloudflare since the last export) keep no block, so validation
    flags them as undocumented instead of inheriting someone else's notes.
    Returns the number of blocks written."""
    written = 0
    for relpath, blocks in harvested.items():
        f = Path(domain_dir) / relpath
        if not f.exists():
            continue
        keys, key_lines, raw = _keyed_lines(f)
        inserts = []
        for key, key_idx in zip(keys, key_lines):
            if key not in blocks or _block_above(raw, key_idx):
                continue  # not documented before, or already documented now
            inserts.append((key_idx, blocks[key]))
        # Bottom-to-top so earlier insertions don't shift the keys below them.
        for key_idx, block in sorted(inserts, reverse=True):
            raw[key_idx:key_idx] = block
        if inserts:
            f.write_text("\n".join(raw) + "\n", encoding="utf-8", newline="\n")
            written += len(inserts)
    return written


def lost(before, domain_dir):
    """['dns/a.yaml:www', ...] for records that are *still in* domain_dir but
    whose documentation block, present in `before`, has gone missing. Empty
    means no documentation was dropped.

    A record deleted in Cloudflare and so dropped from the YAML is not lost
    documentation -- the record itself is gone, and its block went with it.
    Only a record that survived the re-export without its block counts."""
    out = []
    for relpath, blocks in before.items():
        f = Path(domain_dir) / relpath
        if not f.exists():
            continue  # whole file gone: every record in it went too
        keys = set(_keyed_lines(f)[0])
        now = _harvest_file(f)
        out += [f"{relpath}:{key}" for key in blocks if key in keys and key not in now]
    return sorted(out)
