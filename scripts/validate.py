#!/usr/bin/env python3
"""Entry point kept at this exact path for every existing caller (cf.py,
CI workflows, docs): `python3 scripts/validate.py ...`. The actual checks
live in scripts/validation/ (split by concern); see validation/cli.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import yaml  # noqa: F401
except ImportError:
    sys.exit("PyYAML is required: pip install -r requirements.txt")

from validation.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
