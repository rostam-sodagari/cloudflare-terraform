"""Check request-only Origin CA fields against actual issued certificates."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from workflow.certificates import validate_request, verified_values


class CertificateVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.example.com")])

    def request(self, key=None, kind="origin-rsa", days=7):
        csr = x509.CertificateSigningRequestBuilder().subject_name(self.name).sign(key or self.key, hashes.SHA256())
        return {"csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
                "hostnames": ["origin.example.com"], "request_type": kind, "requested_validity": days}

    def certificate(self, key=None, signer=None, names=None, days=7):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.name)
            .public_key((key or self.key).public_key()).serial_number(1234)
            .not_valid_before(start).not_valid_after(start + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in (names or ["origin.example.com"])]), critical=False)
            .sign(signer or self.key, hashes.SHA256()))
        return {"id": "certificate", "certificate": certificate.public_bytes(serialization.Encoding.PEM).decode(),
                "hostnames": names or ["origin.example.com"], "expires_on": certificate.not_valid_after_utc.isoformat()}

    def test_request_fields_are_verified_when_the_api_does_not_echo_them(self):
        request = self.request()
        actual = self.certificate()
        self.assertNotIn("csr", actual)
        self.assertEqual(verified_values(actual, request)["csr"], request["csr"])

    def test_full_inventory_check_detects_wrong_certificates_and_extra_objects(self):
        from workflow import local_review
        provider = "registry.terraform.io/cloudflare/cloudflare"
        kind = "cloudflare_origin_ca_certificate"
        request = self.request()
        actual = self.certificate()
        attributes = {key: {"required": True} for key in ("csr", "hostnames", "request_type")}
        attributes["requested_validity"] = {"optional": True}
        attributes.update({key: {"computed": True} for key in ("id", "certificate", "expires_on")})
        schema = {"provider_schemas": {provider: {"resource_schemas": {kind: {"block": {"attributes": attributes}}}}}}
        candidate = {"resource_changes": [{"address": "certificate", "type": kind, "provider_name": provider,
            "change": {"actions": ["create"], "before": None, "after": request, "after_unknown": {"id": True}}}]}
        before = {"root": "example.com", "observations": {"origin-certificates": {"status": "ok", "value": []}}}
        state = {"values": {"root_module": {"resources": [{"address": "certificate", "values": {**request, "id": "certificate"}}]}}}
        def check(values):
            after = {"root": "example.com", "observations": {"origin-certificates": {"status": "ok", "value": values}}}
            return local_review.verify(before, after, candidate, schema, state)
        self.assertEqual(check([actual]), [])
        self.assertTrue(any("public key" in issue for issue in check([self.certificate(key=self.other)])))
        self.assertTrue(any("outside the planned objects" in issue for issue in check([actual, {**actual, "id": "extra"}])))

    def test_wrong_key_names_signature_duration_and_expiry_are_rejected(self):
        cases = [
            (self.certificate(key=self.other), "public key"),
            (self.certificate(names=["extra.example.com"]), "hostnames"),
            (self.certificate(signer=ec.generate_private_key(ec.SECP256R1())), "signature type"),
            (self.certificate(days=30), "validity"),
            ({**self.certificate(), "expires_on": "2026-02-01T00:00:00+00:00"}, "API expiry"),
        ]
        for actual, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                verified_values(actual, self.request())

    def test_ecc_signature_and_default_validity_are_verified(self):
        signer = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(verified_values(self.certificate(signer=signer), self.request(kind="origin-ecc"))["request_type"], "origin-ecc")
        request = self.request(days=5475)
        request.pop("requested_validity")
        self.assertEqual(verified_values(self.certificate(days=5475), request)["requested_validity"], 5475)

    def test_malformed_or_tampered_csr_is_rejected_before_writes(self):
        with self.assertRaises(ValueError):
            validate_request({"csr": "-----BEGIN CERTIFICATE REQUEST-----\ninvalid"})
        original = x509.load_pem_x509_csr(self.request()["csr"].encode()).public_bytes(serialization.Encoding.DER)
        invalid = x509.load_der_x509_csr(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "signature"):
            validate_request({"csr": invalid.public_bytes(serialization.Encoding.PEM).decode()})


if __name__ == "__main__":
    unittest.main()
