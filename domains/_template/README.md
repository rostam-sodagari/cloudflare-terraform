# Domain template

Not a real domain: CI ignores folders starting with `_`.

`make new` (Windows: `.\cf.ps1 new`) copies this folder for a new domain,
and `make export` uses it as the base for an existing zone, so every
domain has the same files and the same instructions at the top of each
file.

Every YAML file here is fully commented out, so a new domain changes
nothing in Cloudflare until someone removes the `#` from the lines they
want.

To change the instructions in these files, edit `scripts/gen_template.py`
and run `python3 scripts/gen_template.py` (see docs/37-maintaining.md).
