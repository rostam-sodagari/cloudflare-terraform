"""Validate every ruleset mutation without publishing configuration."""
import json
import re
import urllib.error
import urllib.request

from exporting.config import API
from .semantics import writable


def validate_rulesets(client, plan, schema, inventory):
    scope = "accounts" if inventory["root"] == "account" else "zones"
    identity = inventory["identity"]
    if not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise RuntimeError("Invalid ruleset scope identity")
    for resource in plan.get("resource_changes", []):
        change = resource["change"]
        if resource["type"] != "cloudflare_ruleset" or change["actions"] in (["no-op"], ["read"]):
            continue
        if "create" in change["actions"] and "delete" in change["actions"]:
            raise RuntimeError("Ruleset replacement needs separate reviewed removal and creation")
        attributes = schema["provider_schemas"][resource["provider_name"]]["resource_schemas"][resource["type"]]["block"]["attributes"]
        if unknown_configuration(change.get("after_unknown", {}), attributes):
            raise RuntimeError(f"{resource['address']}: ruleset configuration is not fully known; no changes applied")
        before = change.get("before") or {}
        after = change.get("after") or {}
        method = "DELETE" if change["actions"] == ["delete"] else "POST" if change["actions"] == ["create"] else "PUT"
        path = f"/{scope}/{identity}/rulesets"
        if method != "POST":
            ruleset_id = before.get("id")
            if not isinstance(ruleset_id, str) or not re.fullmatch(r"[a-f0-9]{32}", ruleset_id):
                raise RuntimeError("Cannot validate ruleset without a known identity")
            path += "/" + ruleset_id
        payload = writable(after, attributes)
        payload = {key: value for key, value in payload.items() if key not in ("zone_id", "account_id")}
        payload = without_nulls(payload)
        request = urllib.request.Request(API + path + "?dry_run=true", method=method,
            data=None if method == "DELETE" else json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {client.token}", "Content-Type": "application/json"})
        print(f"Validate ruleset without publishing: {resource['address']}")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.status == 204:
                    continue
                result = json.load(response)
        except urllib.error.HTTPError as error:
            try:
                diagnostic = error.read().decode("utf-8", errors="replace")
            finally:
                error.close()
            raise RuntimeError(f"Ruleset validation failed for {resource['address']}: HTTP {error.code}\n{diagnostic}") from None
        except (urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(f"Ruleset validation unavailable; no changes applied: {error}") from None
        for field in ("messages", "warnings", "errors"):
            if result.get(field):
                print(json.dumps({field: result[field]}, ensure_ascii=False))
        if result.get("success") is not True:
            raise RuntimeError(f"Ruleset validation failed for {resource['address']}: {json.dumps(result)}")


def without_nulls(value):
    if isinstance(value, dict):
        return {key: without_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [without_nulls(item) for item in value]
    return value


def unknown_configuration(value, attributes):
    """Computed defaults can be omitted; user configuration must be known."""
    if value is True:
        return True
    if not isinstance(value, dict):
        return False
    for key, marker in value.items():
        spec = attributes[key]
        if spec.get("computed") and not spec.get("required"):
            continue
        nested = spec.get("nested_type")
        if nested:
            children = marker.values() if nested["nesting_mode"] == "map" and isinstance(marker, dict) else marker if isinstance(marker, list) else [marker]
            if any(unknown_configuration(item, nested["attributes"]) for item in children):
                return True
        elif marker is True or isinstance(marker, (list, dict)) and has_unknown(marker):
            return True
    return False


def has_unknown(value):
    if isinstance(value, dict):
        return any(has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(has_unknown(item) for item in value)
    return value is True
