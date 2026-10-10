"""Unit tests for the policy.yaml gate (scripts/validation/policy.py,
Ctx.flag in scripts/validation/common.py): enable/disable and
warning/error severity for best-practice checks."""
import base64
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# See the matching comment in test_validate.py: Report.print() doubles each
# message under GITHUB_ACTIONS=true, which the subprocess below would
# otherwise inherit when these tests themselves run in CI.
SUBPROCESS_ENV = {**os.environ, "GITHUB_ACTIONS": "false"}


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_tlv(tag, value):
    return bytes([tag]) + der_len(len(value)) + value


def fake_rsa_dkim_p(bits):
    """Base64 of a minimal, correctly-shaped DER RSA SubjectPublicKeyInfo
    with an exact bit-length modulus, for testing rsa_key_bits() end to end
    without a real crypto library."""
    n_bytes = bytearray((1 << (bits - 1)).to_bytes((bits + 7) // 8, "big"))
    n_bytes[0] |= 0x80  # make sure the top bit is set, so bit_length() == bits
    if n_bytes[0] & 0x80:
        n_bytes = b"\x00" + bytes(n_bytes)  # DER INTEGER: keep it non-negative
    modulus = der_tlv(0x02, bytes(n_bytes))
    exponent = der_tlv(0x02, (65537).to_bytes(3, "big"))
    rsa_pub = der_tlv(0x30, modulus + exponent)
    bitstring = der_tlv(0x03, b"\x00" + rsa_pub)
    alg_id = der_tlv(0x30, bytes.fromhex("06092a864886f70d0101010500"))  # rsaEncryption + NULL
    spki = der_tlv(0x30, alg_id + bitstring)
    return base64.b64encode(spki).decode()


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        shutil.copytree(REPO, self.repo, ignore=shutil.ignore_patterns(".venv", "graphify-out", "__pycache__", "backend.hcl", ".env", ".env.*", ".git", ".terraform*", ".state", ".export"))
        self.d = self.repo / "domains" / "bad.example"
        shutil.copytree(self.repo / "domains" / "_template", self.d)
        (self.d / "README.md").unlink()
        (self.d / "domain.yaml").write_text(
            'name: bad.example\nzone_id: "0123456789abcdef0123456789abcdef"\nplan: free\n')
        # A zone setting that trips ssl_not_weak by default.
        (self.d / "settings" / "zone.yaml").write_text('ssl: flexible\n')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def set_policy(self, text):
        (self.repo / "policy.yaml").write_text(text)

    def run_validate(self):
        p = subprocess.run([sys.executable, str(self.repo / "scripts" / "validate.py"), str(self.d)],
                           capture_output=True, text=True, env=SUBPROCESS_ENV)
        return p.returncode, p.stdout

    def test_default_is_warning_not_error(self):
        code, out = self.run_validate()
        self.assertIn("WARNING", out)
        self.assertIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 0, out)

    def test_severity_error_fails_validation(self):
        self.set_policy("ssl_not_weak: { enabled: true, severity: error }\n")
        code, out = self.run_validate()
        self.assertIn("ERROR", out)
        self.assertIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 1, out)

    def test_disabled_check_is_silent(self):
        self.set_policy("ssl_not_weak: { enabled: false }\n")
        code, out = self.run_validate()
        self.assertNotIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 0, out)

    def test_missing_policy_yaml_keeps_default_severity(self):
        (self.repo / "policy.yaml").unlink()
        code, out = self.run_validate()
        self.assertIn("WARNING", out)
        self.assertEqual(code, 0, out)

    def test_unlisted_check_defaults_to_enabled_warning(self):
        # policy.yaml exists but doesn't mention ssl_not_weak at all.
        self.set_policy("dmarc_has_rua: { enabled: false }\n")
        code, out = self.run_validate()
        self.assertIn("WARNING", out)
        self.assertIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 0, out)

    def test_plain_dns_records_validate(self):
        (self.d / "dns" / "a.yaml").write_text(
            'root:\n  name: "@"\n  content: 203.0.113.10\n  proxied: true\n',
            encoding="utf-8")
        code, out = self.run_validate()
        self.assertEqual(code, 0, out)

    def test_dmarc_policy_none_warns_not_strict(self):
        (self.d / "dns" / "dmarc.yaml").write_text('"@":\n  policy: none\n  rua: [dmarc@example.com]\n')
        code, out = self.run_validate()
        self.assertIn("monitoring only", out)
        self.assertEqual(code, 0, out)

    def test_dmarc_policy_reject_is_silent(self):
        (self.d / "dns" / "dmarc.yaml").write_text('"@":\n  policy: reject\n  rua: [dmarc@example.com]\n')
        code, out = self.run_validate()
        self.assertNotIn("monitoring only", out)
        self.assertEqual(code, 0, out)

    def test_weak_rsa_dkim_key_warns(self):
        p_value = fake_rsa_dkim_p(1024)
        (self.d / "dns" / "dkim.yaml").write_text(f"google:\n  content: v=DKIM1; k=rsa; p={p_value}\n")
        code, out = self.run_validate()
        self.assertIn("1024-bit RSA", out)
        self.assertIn("weaker than the recommended 2048", out)
        self.assertEqual(code, 0, out)

    def test_strong_rsa_dkim_key_is_silent(self):
        p_value = fake_rsa_dkim_p(2048)
        (self.d / "dns" / "dkim.yaml").write_text(f"google:\n  content: v=DKIM1; k=rsa; p={p_value}\n")
        code, out = self.run_validate()
        self.assertNotIn("weaker than the recommended", out)
        self.assertEqual(code, 0, out)

    def test_ed25519_dkim_key_skips_rsa_size_check(self):
        # 32 raw bytes, not a DER SubjectPublicKeyInfo -- rsa_key_bits() must
        # return None for this rather than misreading it as a tiny RSA key.
        p_value = base64.b64encode(b"\x01" * 32).decode()
        (self.d / "dns" / "dkim.yaml").write_text(f"google:\n  content: v=DKIM1; k=ed25519; p={p_value}\n")
        code, out = self.run_validate()
        self.assertNotIn("weaker than the recommended", out)
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
