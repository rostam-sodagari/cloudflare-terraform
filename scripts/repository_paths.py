"""Resolve repository paths for scripts and nested implementation packages."""
from pathlib import Path


def repository_root(source_file):
    """Find the nearest repository containing cf.py and scripts/.

    Resolve from the caller's file so temporary repository copies work even
    when this helper has already been imported from another checkout.
    """
    for candidate in Path(source_file).resolve().parents:
        if (candidate / "cf.py").is_file() and (candidate / "scripts").is_dir():
            return candidate
    raise RuntimeError(f"Cannot locate the repository containing {source_file}")


ROOT = repository_root(__file__)
