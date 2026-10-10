"""Run sample roots from test fixtures without exposing them to deployment."""
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
from .files import COPY_EXCLUDES


@contextmanager
def fixture_roots(repository):
    fixtures = repository / "tests" / "fixtures" / "domains"
    directories = sorted(path for path in fixtures.glob("*") if path.is_dir())
    if not directories:
        yield []
        return
    with tempfile.TemporaryDirectory(prefix="cloudflare-mock-roots-") as workspace:
        root = Path(workspace)
        ignore = shutil.ignore_patterns(*COPY_EXCLUDES, "*.tfstate", "*.tfstate.*")
        for name in ("modules", "account"):
            shutil.copytree(repository / name, root / name, ignore=ignore)
        roots = []
        for source in directories:
            destination = root / "domains" / source.name
            shutil.copytree(source, destination, ignore=ignore)
            roots.append(SimpleNamespace(name=source.name, dir=destination))
        yield roots
