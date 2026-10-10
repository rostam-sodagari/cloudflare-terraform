"""
Carry '##' record documentation blocks across a re-export.

A re-export rebuilds YAML from a data dict, and yaml.safe_dump cannot keep
comments, so the '## Owner/Purpose/Impact' blocks above each DNS record would
be lost (docs/41-record-documentation.md). harvest() reads them off the live
folder, reinject() puts them back matched by record key, and lost() reports
any that went missing. Same scan as validation's check_record_doc_blocks().
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from repository_paths import repository_root
ROOT = repository_root(__file__)

from yamlio import load_with_lines  # noqa: E402
from config import DOC_BLOCK_RE  # noqa: E402
from validation.record_documentation import top_level_key_lines  # noqa: E402

# kind -> needs a "Proxy" line too. Also used by backfill_record_docs.py.
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
    """Put harvested blocks back, matched by record key; returns how many.

    A record that is new upstream gets no block, so validation flags it rather
    than letting it inherit someone else's notes."""
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
    """['dns/a.yaml:www', ...] for records still in domain_dir that lost the
    block they had in `before`. A record deleted upstream is not loss -- the
    record itself is gone, and its block went with it."""
    out = []
    for relpath, blocks in before.items():
        f = Path(domain_dir) / relpath
        if not f.exists():
            continue  # whole file gone: every record in it went too
        keys = set(_keyed_lines(f)[0])
        now = _harvest_file(f)
        out += [f"{relpath}:{key}" for key in blocks if key in keys and key not in now]
    return sorted(out)
