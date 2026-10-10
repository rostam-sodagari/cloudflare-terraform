"""Dkim helpers for configuration validation."""


def dkim_tags(text):
    """Parse a DKIM TXT value ('v=DKIM1; k=rsa; p=...') into {tag: value}."""
    tags = {}
    for part in text.split(";"):
        part = part.strip()
        if "=" in part:
            tag_name, _, tag_value = part.partition("=")
            tags[tag_name.strip().lower()] = tag_value.strip()
    return tags

def _der_tlv(data, i):
    """One DER tag-length-value at offset i. Minimal: no indefinite lengths,
    no multi-byte tags -- plenty for the plain SubjectPublicKeyInfo/RSAPublicKey
    shapes a DKIM p= value holds."""
    offset = i
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        length_bytes = length & 0x7F
        length = int.from_bytes(data[offset:offset + length_bytes], "big")
        offset += length_bytes
    return tag, data[offset:offset + length], offset + length

def rsa_key_bits(der):
    """Bit length of the modulus in a DER-encoded RSA SubjectPublicKeyInfo
    (what DKIM's p= holds for k=rsa, RFC 6376). None if der isn't one -- for
    example an Ed25519 key (RFC 8463), which has no modulus to size."""
    try:
        tag, spki, _ = _der_tlv(der, 0)
        if tag != 0x30:
            return None
        _, _, algorithm_end = _der_tlv(spki, 0)  # AlgorithmIdentifier SEQUENCE, skipped
        tag, bitstring, _ = _der_tlv(spki, algorithm_end)
        if tag != 0x03:
            return None
        tag, rsa_key, _ = _der_tlv(bitstring[1:], 0)  # drop the "unused bits" byte
        if tag != 0x30:
            return None
        tag, modulus, _ = _der_tlv(rsa_key, 0)
        if tag != 0x02:
            return None
        return int.from_bytes(modulus, "big").bit_length()
    except (IndexError, ValueError):
        return None
