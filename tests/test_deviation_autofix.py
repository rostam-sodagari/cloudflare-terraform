"""
Tests for scripts/deviation_autofix.py, which commits straight to main with no
human review -- so what it refuses to do matters more than what it does.

Runs the real script in a throwaway git repo against tests/fixtures/zone_api.json.
A harness written into that copy stubs the API client and run_deviation_check
(the real one shells out to Terraform and needs live credentials).
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
import deviation_autofix, export_zone

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
# Terraform transport is exercised independently in reconciliation tests.
deviation_autofix.state_bindings = lambda path: {}
deviation_autofix.reconcile = lambda path, snapshot=None: None
class FakeJournal:
    def __init__(self, root): pass
    def start(self, *args, **kwargs): pass
    def finish(self, *args, **kwargs): pass
deviation_autofix.Journal = FakeJournal

if os.environ.get("HARNESS_DELETE_FILE"):
    doomed = deviation_autofix.ROOT / os.environ["HARNESS_DELETE_FILE"]
    _copy = deviation_autofix.copy_yaml

    def copy_then_delete(staging, dest):
        n = _copy(staging, dest)
        doomed.unlink(missing_ok=True)
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
            ".venv", "graphify-out", "__pycache__", "backend.hcl", ".env", ".env.*",
            ".git", ".terraform*", ".state", ".export"))

        # A live domain folder using example.com's fixture under acme.example's identity.
        cls.domain_dir = cls.repo / "domains" / DOMAIN
        shutil.copytree(cls.repo / "tests" / "fixtures" / "domains" / "example.com", cls.domain_dir)
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

    # ---- the happy path -------------------------------------------------
    def test_resync_commits_exported_configuration(self):
        rc, out = self.run_autofix()
        self.assertEqual(rc, 0, out)
        self.assertIn("committed and pushed", out)
        self.assertNotEqual(self.head(), self.base, "nothing was committed")
        self.assertIn(f"Sync {DOMAIN} with live Cloudflare state",
                      self._git("log", "-1", "--pretty=%s%n%b").stdout)

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
        before = {p.relative_to(self.domain_dir): p.read_bytes() for p in self.domain_dir.rglob('*.yaml')}
        rc, out = self.run_autofix(HARNESS_DRIFT="changed")
        self.assertNotEqual(rc, 0)
        self.assertIn("changed while this resync was running", out)
        self.assertNothingCommitted(out)
        self.assertEqual(before, {p.relative_to(self.domain_dir): p.read_bytes() for p in self.domain_dir.rglob('*.yaml')})

    def test_aborts_when_a_file_would_be_deleted(self):
        before = (self.domain_dir / 'main.tf').read_bytes()
        rc, out = self.run_autofix(HARNESS_DELETE_FILE=f"domains/{DOMAIN}/main.tf")
        self.assertNotEqual(rc, 0)
        self.assertIn("would delete", out)
        self.assertNothingCommitted(out)
        self.assertEqual((self.domain_dir / 'main.tf').read_bytes(), before)

    def test_aborts_when_the_deviation_recheck_fails(self):
        rc, out = self.run_autofix(HARNESS_DRIFT="fail")
        self.assertNotEqual(rc, 0)
        self.assertIn("re-check failed", out)
        self.assertNothingCommitted(out)

    def test_refuses_dirty_root_before_export(self):
        target = self.domain_dir / 'dns/a.yaml'
        local_change = target.read_bytes() + b'\n# local work\n'
        target.write_bytes(local_change)
        rc, out = self.run_autofix()
        self.assertNotEqual(rc, 0)
        self.assertIn('clean checkout', out)
        self.assertNothingCommitted(out)
        self.assertEqual(target.read_bytes(), local_change)

    def test_refuses_unrelated_staged_changes(self):
        target = self.repo / 'README.md'
        target.write_bytes(target.read_bytes() + b'\nlocal work\n')
        self._git('add', 'README.md')
        rc, out = self.run_autofix()
        self.assertNotEqual(rc, 0)
        self.assertIn('no staged changes', out)
        self.assertNothingCommitted(out)

    def test_refuses_unstaged_shared_code_changes(self):
        target = self.repo / 'scripts/export_zone.py'
        local_change = target.read_bytes() + b'\n# unfinished shared code\n'
        target.write_bytes(local_change)
        rc, out = self.run_autofix()
        self.assertNotEqual(rc, 0)
        self.assertIn('clean checkout', out)
        self.assertNothingCommitted(out)
        self.assertEqual(target.read_bytes(), local_change)

    def test_refuses_checkout_ahead_of_target_branch(self):
        target = self.repo / 'README.md'
        target.write_bytes(target.read_bytes() + b'\nUnreviewed branch change\n')
        self._git('add', 'README.md')
        self._git('commit', '-m', 'Unreviewed branch change')
        revision = self.head()
        rc, out = self.run_autofix()
        self.assertNotEqual(rc, 0)
        self.assertIn('current target branch revision', out)
        self.assertEqual(self.head(), revision)


if __name__ == "__main__":
    unittest.main()
