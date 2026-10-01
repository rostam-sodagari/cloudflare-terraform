"""
Shared YAML helpers for validate.py, export_zone.py and plan_summary.py.

load_with_lines(path) parses a YAML file and returns (data, lines) where
`lines` maps a path tuple such as ("www", "content") or (0, "expression")
to its 1-based line number. Duplicate keys are reported as errors, because
plain YAML loaders silently keep only the last one, which would quietly
drop a DNS record or rule.
"""
from pathlib import Path

import yaml
from yaml.constructor import SafeConstructor
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


class DuplicateKeyError(Exception):
    def __init__(self, key, first_line, second_line):
        super().__init__(f"duplicate key '{key}' (lines {first_line} and {second_line})")
        self.key = key
        self.line = second_line
        self.first_line = first_line


_constructor = SafeConstructor()


def _build(node, path, lines):
    lines[path] = node.start_mark.line + 1
    if isinstance(node, MappingNode):
        out, seen = {}, {}
        _constructor.flatten_mapping(node)
        for k_node, v_node in node.value:
            key = _constructor.construct_object(k_node, deep=True)
            if isinstance(key, (list, dict)):
                key = str(key)
            if key in seen:
                raise DuplicateKeyError(key, seen[key], k_node.start_mark.line + 1)
            seen[key] = k_node.start_mark.line + 1
            out[key] = _build(v_node, path + (key,), lines)
        return out
    if isinstance(node, SequenceNode):
        return [_build(v, path + (i,), lines) for i, v in enumerate(node.value)]
    if isinstance(node, ScalarNode):
        return _constructor.construct_object(node, deep=True)
    return _constructor.construct_object(node, deep=True)


def load_with_lines(path):
    """Return (data, lines). data is None for a missing, empty or comment-only file."""
    p = Path(path)
    if not p.exists():
        return None, {}
    text = p.read_text(encoding="utf-8")
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    if node is None:
        return None, {}
    lines = {}
    return _build(node, (), lines), lines


def line_for(lines, path):
    """Closest known line for a path (walks up to the parent if needed)."""
    path = tuple(path)
    while path:
        if path in lines:
            return lines[path]
        path = path[:-1]
    return lines.get((), 1)


def header_of(template_file):
    """The leading comment block of a template file (its documentation)."""
    p = Path(template_file)
    if not p.exists():
        return ""
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            out.append(line)
        else:
            break
    # Drop a trailing "--- ... data below this line ---" marker (and the "#"
    # spacer before it) so a re-export does not repeat it.
    while out and (not out[-1].strip() or out[-1].startswith("# ---") or out[-1].strip() == "#"):
        out.pop()
    return "\n".join(out)


def dump_with_header(dest, data, header, note=None):
    """Write data as YAML below a documentation header. Empty data writes the header only."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    parts = [header] if header else []
    if note:
        parts.append(f"#\n# {note}")
    if data:
        body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=1000, default_flow_style=False)
        parts.append(body.rstrip("\n"))
    dest.write_text("\n".join(parts).rstrip("\n") + "\n", encoding="utf-8", newline="\n")
