"""Personalize the copied template instructions without changing YAML data."""
from pathlib import Path


def personalize_zone(directory, domain_name):
    directory = Path(directory)
    guide = directory / "README.md"
    if guide.is_file():
        guide.write_text(guide.read_text(encoding="utf-8").replace("{{DOMAIN}}", domain_name),
                         encoding="utf-8", newline="\n")
    for config_file in directory.rglob("*.yaml"):
        text = config_file.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        updated = "".join(line.replace("example.com", domain_name)
                          if line.startswith("#") else line for line in lines)
        if updated != text:
            config_file.write_text(updated, encoding="utf-8", newline="\n")
