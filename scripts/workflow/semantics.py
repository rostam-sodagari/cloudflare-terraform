"""Compare complete plan effects without hiding writable configuration."""
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def resources(module):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from resources(child)


def writable(value, attributes):
    """Use provider schema, not a global list of names, to exclude computed fields."""
    if value is None:
        return None
    if not isinstance(value, dict):
        return value
    result = {}
    for name, item in value.items():
        spec = attributes.get(name)
        if spec is None:
            raise ValueError(f"Provider schema has no field {name!r}; comparison is incomplete")
        if not (spec.get("optional") or spec.get("required")):
            continue
        nested = spec.get("nested_type")
        primitive = spec.get('type')
        if isinstance(primitive, list) and primitive[0] == 'set' and isinstance(item, list):
            item = sorted(item, key=digest)
        if nested and item is not None and not isinstance(item, bool):
            children = nested["attributes"]
            mode = nested["nesting_mode"]
            if mode == "single":
                item = writable(item, children)
            elif mode == "map":
                item = {key: writable(entry, children) for key, entry in item.items()}
            else:
                item = [writable(entry, children) for entry in item]
                if mode == "set":
                    item = sorted(item, key=digest)
        result[name] = item
    return result


def effects(plan, provider_schema):
    schemas = provider_schema["provider_schemas"]
    result = []
    for resource in plan.get("resource_changes", []):
        if resource.get("mode") == "data":
            continue
        change = resource["change"]
        if change["actions"] == ["no-op"] and not change.get("importing"):
            continue
        spec = schemas[resource["provider_name"]]["resource_schemas"][resource["type"]]
        attributes = spec["block"]["attributes"]
        result.append({"address": resource["address"], "type": resource["type"],
                       "actions": change["actions"], "importing": change.get("importing"),
                       "before": writable(change.get("before"), attributes),
                       "after": writable(change.get("after"), attributes),
                       "unknown": writable(change.get("after_unknown", {}), attributes)})
    return sorted(result, key=lambda item: item["address"])


def state_only(plan):
    """An import must be a no-op too: import-and-update is a live mutation."""
    return all(resource.get("mode") == "data" or resource["change"]["actions"] in
               (["no-op"], ["read"]) for resource in plan.get("resource_changes", []))


def mask_sensitive(value, marker):
    if marker is True:
        return '[redacted]'
    if isinstance(value, dict):
        return {key: mask_sensitive(item, marker.get(key, False) if isinstance(marker, dict) else False)
                for key, item in value.items()}
    if isinstance(value, list):
        return [mask_sensitive(item, marker[index] if isinstance(marker, list) and index < len(marker) else False)
                for index, item in enumerate(value)]
    return value


def reported_effects(plan, provider_schema):
    changes = {item['address']: item['change'] for item in plan.get('resource_changes', [])}
    result = effects(plan, provider_schema)
    for item in result:
        change = changes[item['address']]
        item['before'], item['after'] = sensitive_pair(item['before'], item['after'],
            change.get('before_sensitive', False), change.get('after_sensitive', False))
    return result


def sensitive_pair(before, after, before_marker=False, after_marker=False):
    """Mask sensitive values while retaining whether the value actually changed."""
    if before_marker is True or after_marker is True:
        return (('[redacted]', '[redacted]') if before == after else
                ('[redacted before]', '[redacted after]'))
    if isinstance(before, dict) or isinstance(after, dict):
        left = before if isinstance(before, dict) else {}
        right = after if isinstance(after, dict) else {}
        pairs = {key: sensitive_pair(left.get(key), right.get(key),
                                    before_marker.get(key, False) if isinstance(before_marker, dict) else False,
                                    after_marker.get(key, False) if isinstance(after_marker, dict) else False)
                 for key in set(left) | set(right)}
        return ({key: pairs[key][0] for key in left} if isinstance(before, dict) else before,
                {key: pairs[key][1] for key in right} if isinstance(after, dict) else after)
    if isinstance(before, list) or isinstance(after, list):
        left = before if isinstance(before, list) else []
        right = after if isinstance(after, list) else []
        pairs = [sensitive_pair(left[index] if index < len(left) else None,
                               right[index] if index < len(right) else None,
                               before_marker[index] if isinstance(before_marker, list) and index < len(before_marker) else False,
                               after_marker[index] if isinstance(after_marker, list) and index < len(after_marker) else False)
                 for index in range(max(len(left), len(right)))]
        return ([pair[0] for pair in pairs[:len(left)]] if isinstance(before, list) else before,
                [pair[1] for pair in pairs[:len(right)]] if isinstance(after, list) else after)
    return before, after


def bindings(state):
    result = {}
    for resource in resources(state.get("values", {}).get("root_module", {})):
        if resource.get("mode") == "data":
            continue
        values = resource.get("values") or {}
        identity = values.get("id")
        if not identity:
            continue
        result[str(identity)] = resource["address"]
        result[f"{resource.get('type', '')}|{identity}"] = resource["address"]
        parent = values.get("zone_id") or values.get("account_id")
        if parent and not str(identity).startswith(str(parent) + "/"):
            result[f"{parent}/{identity}"] = resource["address"]
            result[f"{resource.get('type', '')}|{parent}/{identity}"] = resource["address"]
            result[f"zones/{parent}/{identity}"] = resource["address"]
    return result
