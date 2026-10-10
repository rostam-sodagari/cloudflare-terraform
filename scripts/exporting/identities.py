"""Keep existing DNS and access-rule keys bound to Cloudflare object IDs."""
import json
import re
from .converters import unique


class Identities:
    def __init__(self, bindings=None):
        self.preferred = {}
        self.reserved = {}
        for import_id, address in (bindings or {}).items():
            import_id = import_id.split("|", 1)[-1]
            match = re.search(r'cloudflare_dns_record\.(?:this|structured)\[(".*")\]$', address)
            if match:
                kind, key = json.loads(match[1]).split("/", 1)
                self.preferred[(kind, import_id)] = key
                self.reserved.setdefault(kind, set()).add(key)
            match = re.search(r'cloudflare_access_rule\.this\[(".*")\]$', address)
            if match:
                key = json.loads(match[1])
                self.preferred[("access", import_id)] = key
                self.reserved.setdefault("access", set()).add(key)
            match = re.search(r'cloudflare_email_routing_rule\.this\[(".*")\]$', address)
            if match:
                key = json.loads(match[1])
                self.preferred[("email", import_id)] = key
                self.reserved.setdefault("email", set()).add(key)

    def key(self, kind, proposed, import_id, used):
        preferred = self.preferred.get((kind, import_id))
        if preferred is not None:
            if preferred in used:
                raise RuntimeError(f"Duplicate binding for {kind}/{preferred}; refusing ambiguous export")
            used.add(preferred)
            return preferred
        unavailable = used | self.reserved.get(kind, set())
        key = unique(proposed, unavailable)
        used.add(key)
        return key
