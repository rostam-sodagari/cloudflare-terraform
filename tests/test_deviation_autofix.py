"""
Tests for scripts/deviation_autofix.py, which commits straight to main with no
human review -- so what it refuses to do matters more than what it does.

Runs the real script as a subprocess inside a throwaway git repo, against the
recorded Cloudflare responses in tests/fixtures/zone_api.json. A harness module
written into that copy patches the two things we cannot have in a test: the API
client (replaced with the fixture) and run_deviation_check (replaced with a stub,
since the real one shells out to Terraform and needs live credentials).

Run: python3 -m unittest discover -s tests
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ZONE = "0123456789abcdef0123456789abcdee"
DOMAIN = "acme.example"

# Patches the API client and the Terraform-backed deviation check, then runs the
# real main(). Knobs come in through the environment so each test can bend one
# thing and leave the rest honest.
HARNESS = '''
import json, os, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import deviation_autofix, export_zone, record_docs

fixture = json.loads(Path(os.environ["HARNESS_FIXTURE"]).read_text(encoding="utf-8"))


def get(self, path, params=None):
    if path not in fixture:
        raise export_zone.NotFound(path)
    return {"result": fixture[path], "result_info": {"total_pages": 1}}


export_zone.Client.get = get


class Done:
    def __init__(self, rc):
        self.returncode, self.stdout, self.stderr = rc, "", ""


mode = os.environ.get("HARNESS_DRIFT", "stable")


def fake_check(root):
    if mode == "fail":
        return Done(1)
    if mode == "changed":
        f = deviation_autofix.ROOT / "domains" / root / "deviation.json"
        f.write_text(json.dumps({"resource_drift": [{"address": "appeared.mid.export"}]}),
                     encoding="utf-8")
    return Done(2)


deviation_autofix.run_deviation_check = fake_check

if os.environ.get("HARNESS_SKIP_REINJECT") == "1":
    record_docs.reinject = lambda *a, **k: 0

if os.environ.get("HARNESS_DELETE_FILE"):
    doomed = deviation_autofix.ROOT / os.environ["HARNESS_DELETE_FILE"]
    _copy = deviation_autofix.copy_yaml

    def copy_then_delete(staging, dest):
        n = _copy(staging, dest)
        doomed.unlink()
        return n

    deviation_autofix.copy_yaml = copy_then_delete

deviation_autofix.main()
'''

DOMAIN_YAML = f"""# domain.yaml for the autofix test
name: {DOMAIN}
zone_id: "{ZONE}"
plan: pro
owner: platform-team
"""


class AutofixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.repo = cls.tmp / "repo"
        shutil.copytree(REPO, cls.repo, ignore=shutil.ignore_patterns(
            ".git", ".terraform*", ".state", ".export", ".audit", ".venv", "__pycache__"))

        # A live domain folder for the fixture's zone: example.com's YAML (which
        # carries real '##' documentation blocks) under acme.example's identity.
        cls.domain_dir = cls.repo / "domains" / DOMAIN
        shutil.copytree(cls.repo / "domains" / "example.com", cls.domain_dir)
        (cls.domain_dir / "domain.yaml").write_text(DOMAIN_YAML, encoding="utf-8", newline="\n")
        # A service this repo's exporter does not cover: it must survive untouched.
        (cls.domain_dir / "security" / "total-tls.yaml").write_text(
            "# security/total-tls.yaml\nenabled: true\n", encoding="utf-8", newline="\n")
        # Terraform's local cache and provider lock live in here too.
        (cls.domain_dir / ".terraform").mkdir(exist_ok=True)
        (cls.domain_dir / ".terraform" / "marker").write_text("cache\n", encoding="utf-8")
        (cls.domain_dir / ".terraform.lock.hcl").write_text('# lock\n', encoding="utf-8")

        (cls.repo / "scripts" / "_autofix_harness.py").write_text(HARNESS, encoding="utf-8")

        cls.origin = cls.tmp / "origin.git"
        cls._git("init", "--bare", str(cls.origin), cwd=cls.tmp)
        cls._git("init", "-b", "main")
        cls._git("config", "user.email", "test@example.invalid")
        cls._git("config", "user.name", "test")
        cls._git("remote", "add", "origin", str(cls.origin))
        cls._git("add", "-A")
        cls._git("commit", "-m", "baseline")
        cls._git("push", "-u", "origin", "main")
        cls.base = cls._git("rev-parse", "HEAD").stdout.strip()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _git(cls, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=str(cwd or cls.repo),
                              capture_output=True, text=True)

    def setUp(self):
        # Every test starts from the baseline commit: the autofix commits, so
        # tests would otherwise see each other's work.
        self._git("reset", "--hard", self.base)
        self._git("clean", "-fd")
        self._git("push", "--force", "origin", f"{self.base}:main")
        (self.domain_dir / "deviation.json").write_text(
            json.dumps({"resource_drift": [{"address": "module.domain.module.dns."
                                            "cloudflare_dns_record.this[\"www\"]"}]}),
            encoding="utf-8")

    def run_autofix(self, root=DOMAIN, **env):
        e = dict(os.environ)
        e["CLOUDFLARE_API_TOKEN"] = "test"
        e["HARNESS_FIXTURE"] = str(self.repo / "tests" / "fixtures" / "zone_api.json")
        e.update({k: str(v) for k, v in env.items()})
        proc = subprocess.run(
            [sys.executable, str(self.repo / "scripts" / "_autofix_harness.py"), root],
            cwd=str(self.repo), capture_output=True, text=True, env=e)
        return proc.returncode, proc.stdout + proc.stderr

    def head(self):
        return self._git("rev-parse", "HEAD").stdout.strip()

    def assertNothingCommitted(self, out):
        self.assertEqual(self.head(), self.base, f"a commit was made despite aborting:\n{out}")

    def blocks(self, relpath="dns/a.yaml"):
        from scripts.record_docs import _harvest_file
        return _harvest_file(self.domain_dir / relpath)

    # ---- the happy path -------------------------------------------------
    def test_resync_commits_and_keeps_record_documentation(self):
        documented_before = set(self.blocks())
        rc, out = self.run_autofix()
        self.assertEqual(rc, 0, out)
        self.assertIn("committed and pushed", out)
        self.assertNotEqual(self.head(), self.base, "nothing was committed")
        self.assertIn(f"Sync {DOMAIN} with live Cloudflare state",
                      self._git("log", "-1", "--pretty=%s%n%b").stdout)

        # Records that still exist upstream keep their blocks; 'api' is not in
        # the fixture, so it is legitimately gone along with its block.
        after = self.blocks()
        self.assertTrue(after, "all documentation was lost")
        for key in documented_before & set(after):
            self.assertTrue(after[key], f"{key} lost its documentation block")
        self.assertIn("root", after)

    def test_identity_and_unexported_files_are_left_alone(self):
        rc, out = self.run_autofix()
        self.assertEqual(rc, 0, out)
        # domain.yaml keeps the human-maintained owner (the exporter writes
        # "change-me" into its own copy).
        self.assertIn("owner: platform-team", (self.domain_dir / "domain.yaml").read_text(encoding="utf-8"))
        # Total TLS is not exported by this repo, so the blank template must
        # not have been copied over it.
        self.assertIn("enabled: true",
                      (self.domain_dir / "security" / "total-tls.yaml").read_text(encoding="utf-8"))
        # Terraform's cache and lock file are no longer collateral damage.
        self.assertTrue((self.domain_dir / ".terraform" / "marker").exists())
        self.assertTrue((self.domain_dir / ".terraform.lock.hcl").exists())
        # Files the exporter never writes.
        self.assertTrue((self.domain_dir / "main.tf").exists())
        self.assertTrue((self.domain_dir / "tests" / "plan.tftest.hcl").exists())

    # ---- the refusals ---------------------------------------------------
    def test_aborts_when_cloudflare_changes_mid_export(self):
        rc, out = self.run_autofix(HARNESS_DRIFT="changed")
        self.assertNotEqual(rc, 0)
        self.assertIn("changed while this resync was running", out)
        self.assertNothingCommitted(out)

    def test_aborts_when_documentation_would_be_dropped(self):
        """The whole point of record_docs: without the carry-across, this is
        exactly what the old --force export did on every run."""
        rc, out = self.run_autofix(HARNESS_SKIP_REINJECT=1)
        self.assertNotEqual(rc, 0)
        self.assertIn("dropped record documentation", out)
        self.assertNothingCommitted(out)

    def test_aborts_when_a_file_would_be_deleted(self):
        rc, out = self.run_autofix(HARNESS_DELETE_FILE=f"domains/{DOMAIN}/main.tf")
        self.assertNotEqual(rc, 0)
        self.assertIn("would delete", out)
        self.assertNothingCommitted(out)

    def test_aborts_when_the_deviation_recheck_fails(self):
        rc, out = self.run_autofix(HARNESS_DRIFT="fail")
        self.assertNotEqual(rc, 0)
        self.assertIn("re-check failed", out)
        self.assertNothingCommitted(out)


if __name__ == "__main__":
    unittest.main()
