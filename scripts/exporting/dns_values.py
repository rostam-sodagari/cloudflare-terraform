"""Compare Email Routing's DNS preview with DNS API record encodings."""
from yamlio import unquote_txt


def dns_values(record):
    values = dict(record)
    if isinstance(values.get("name"), str):
        values["name"] = values["name"].rstrip(".").lower()
    if values.get("type") == "MX":
        values["content"] = values["content"].rstrip(".").lower()
    elif values.get("type") == "TXT":
        content, quoted = unquote_txt(values["content"])
        if quoted is None:
            raise ValueError("Malformed TXT encoding in Email Routing DNS records")
        values["content"] = content
    return values


def matches_dns(record, expected):
    actual, desired = dns_values(record), dns_values(expected)
    return all(actual.get(key) == value for key, value in desired.items() if value is not None)


def conflicts_with_email_dns(record, required):
    actual, expected = dns_values(record), dns_values(required)
    if actual.get("type") != expected.get("type") or actual.get("name") != expected.get("name"):
        return False
    if expected["type"] == "TXT" and expected["content"].startswith("v=spf1"):
        return (actual.get("content") or "").startswith("v=spf1")
    return True
