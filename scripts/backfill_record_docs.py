#!/usr/bin/env python3
"""
One-off: insert a placeholder '##' documentation block above every DNS
record in a domain that doesn't already have one, so `record_has_doc_block`
(policy.yaml) has something to build on. Not part of CI or any other
script -- run it by hand per domain, then fill in the placeholders and
delete them where they don't apply:

    python3 scripts/backfill_record_docs.py domains/example.com
    python3 scripts/backfill_record_docs.py domains/example.com domains/example.net

See docs/41-record-documentation.md for the block's format.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from yamlio import load_with_lines  # noqa: E402
from validation.common import DOC_BLOCK_RE, DOC_BLOCK_REQUIRED, top_level_key_lines  # noqa: E402

# kind (from the filename) -> needs a "Proxy" line too
DNS_FILES = {
    "a": True, "aaaa": True, "cname": True, "mx": False, "txt": False, "ns": False,
    "spf": False, "dmarc": False, "dkim": False, "caa": False, "srv": False,
}


def placeholder(needs_proxy):
    lines = [f"## {name.title()}: change-me" for name in DOC_BLOCK_REQUIRED]
    if needs_proxy:
        lines.append("## Proxy: change-me")
    return lines


def backfill_file(f, needs_proxy):
    data, _ = load_with_lines(f)
    if not isinstance(data, dict) or not data:
        return 0
    raw = f.read_text(encoding="utf-8").splitlines()
    key_lines = top_level_key_lines(raw)
    # Process bottom-to-top so earlier insertions don't shift line numbers
    # for keys not yet processed.
    inserts = []
    for key, key_idx in zip(data, key_lines):
        i = key_idx - 1
        has_block = i >= 0 and DOC_BLOCK_RE.match(raw[i])
        if not has_block:
            inserts.append(key_idx)  # 0-based index to insert before
    for idx in sorted(inserts, reverse=True):
        raw[idx:idx] = placeholder(needs_proxy)
    if inserts:
        f.write_text("\n".join(raw) + "\n", encoding="utf-8", newline="\n")
    return len(inserts)


def backfill_domain(domain_dir):
    d = Path(domain_dir)
    total = 0
    for kind, needs_proxy in DNS_FILES.items():
        f = d / "dns" / f"{kind}.yaml"
        if f.exists():
            n = backfill_file(f, needs_proxy)
            if n:
                print(f"{f}: added {n} placeholder block(s)")
            total += n
    return total


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    total = sum(backfill_domain(d) for d in sys.argv[1:])
    print(f"\n{total} placeholder block(s) added. Fill them in, then run "
          f"python3 cf.py validate <domain> to confirm 'Nothing will change' still holds.")


if __name__ == "__main__":
    main()
