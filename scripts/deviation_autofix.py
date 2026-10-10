#!/usr/bin/env python3
"""Compatibility entry point for guarded deviation resync."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workflow import resync as _implementation

if __name__ == "__main__":
    _implementation.main()
else:
    # Imports return the implementation itself, preserving patched globals.
    sys.modules[__name__] = _implementation
