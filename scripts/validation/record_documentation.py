"""Record documentation helpers for configuration validation."""
from config import DOC_BLOCK_RE, DOC_BLOCK_REQUIRED


def top_level_key_lines(raw):
    """0-based indices of lines that start a top-level ('column 0') key, in
    file order. yamlio's `lines` map tracks where each key's *value* starts
    (one line below the key for a normal block mapping), not the key line
    itself, so record-doc-block scanning -- which needs the key's own line
    -- pairs this up with dict key order instead (both are file order)."""
    return [line_index for line_index, line in enumerate(raw) if line and not line[0].isspace() and not line.startswith("#") and ":" in line]

def check_record_doc_blocks(ctx, f, data, needs_proxy=False):
    """Every DNS record needs a '##' documentation block (Owner, Purpose,
    Impact, and Proxy for record types that support proxied) on the lines
    directly above its key. Gated through policy.yaml ('record_has_doc_block')
    like any other best-practice check -- see docs/41-record-documentation.md."""
    config_file = f
    if not isinstance(data, dict) or not data:
        return
    raw = config_file.read_text(encoding="utf-8").splitlines()
    key_lines = top_level_key_lines(raw)
    required = list(DOC_BLOCK_REQUIRED) + (["proxy"] if needs_proxy else [])
    for key, key_line_index in zip(data, key_lines):
        found = set()
        line_index = key_line_index - 1
        while line_index >= 0:
            match = DOC_BLOCK_RE.match(raw[line_index])
            if not match:
                break
            found.add(match.group(1).lower())
            line_index -= 1
        missing = [name for name in required if name not in found]
        if missing:
            ctx.flag("record_has_doc_block", (key,),
                     f"'{key}' has no '##' documentation block ({', '.join(n.title() for n in missing)} missing).",
                     "add lines directly above it, e.g. \"## Owner: ...\", \"## Purpose: ...\", \"## Impact: ...\""
                     + (', "## Proxy: ..."' if needs_proxy else "") + " -- see docs/41-record-documentation.md")
