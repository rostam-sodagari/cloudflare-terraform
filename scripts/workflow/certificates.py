"""Verify Origin CA request fields from the issued X.509 certificate."""
from datetime import timedelta


def validate_request(request):
    from cryptography import x509
    csr = x509.load_pem_x509_csr(request["csr"].encode("ascii"))
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    return csr


def verified_values(actual, request):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import SignatureAlgorithmOID
    csr = validate_request(request)
    certificate = x509.load_pem_x509_certificate(actual["certificate"].encode("ascii"))
    def public_key(value):
        return value.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    if public_key(csr) != public_key(certificate):
        raise ValueError("issued certificate public key does not match the reviewed CSR")
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as error:
        raise ValueError("issued certificate is missing its hostname extension") from error
    if any(not isinstance(name, x509.DNSName) for name in names) or sorted(names.get_values_for_type(x509.DNSName)) != sorted(request["hostnames"]):
        raise ValueError("issued certificate hostnames do not match the reviewed hostnames")
    algorithms = {
        "origin-rsa": {SignatureAlgorithmOID.RSA_WITH_SHA256, SignatureAlgorithmOID.RSA_WITH_SHA384, SignatureAlgorithmOID.RSA_WITH_SHA512},
        "origin-ecc": {SignatureAlgorithmOID.ECDSA_WITH_SHA256, SignatureAlgorithmOID.ECDSA_WITH_SHA384, SignatureAlgorithmOID.ECDSA_WITH_SHA512},
    }
    if certificate.signature_algorithm_oid not in algorithms.get(request["request_type"], set()):
        raise ValueError("issued certificate signature type does not match the reviewed request")
    days = request.get("requested_validity") or 5475
    if certificate.not_valid_after_utc - certificate.not_valid_before_utc != timedelta(days=days):
        raise ValueError("issued certificate validity does not match the reviewed duration")
    from datetime import datetime
    expiry = actual["expires_on"].replace(" +0000 UTC", "+00:00").replace("Z", "+00:00")
    if datetime.fromisoformat(expiry) != certificate.not_valid_after_utc:
        raise ValueError("API expiry does not match the issued certificate")
    return {**actual, "csr": request["csr"], "request_type": request["request_type"], "requested_validity": days}
