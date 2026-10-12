"""Read configuration inventories, including unsupported configuration, without writes."""
import json
import copy
from pathlib import Path
from exporting.client import NotFound, UnavailableForPlan, SettingUnavailable
from .coverage import services, endpoint
from .semantics import digest
from exporting.config import RULE_SCHEMA
from exporting.converters import clean
from exporting.secrets import sensitive_webhook

BOOKKEEPING = {"created_on", "modified_on", "created_at", "updated_at", "last_updated",
               "comment_modified_on", "tags_modified_on", "num_items", "num_referencing_filters",
               "editable", "using_latest_model", "stale_zone_configuration", 'updated_on',
               'last_success', 'last_failure', 'last_complete', 'last_error', 'error_message', 'uploaded_on'}
REDACT = {"secret", "value_secret", "private_key", "password", "token"}


def canonical(value, *, unordered=False):
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items() if key not in BOOKKEEPING
                and not (value.get("id") == "development_mode" and key == "time_remaining")}
    if isinstance(value, list):
        result = [canonical(item) for item in value]
        return sorted(result, key=digest) if unordered else result
    return value


def redact(value):
    if isinstance(value, dict):
        return {key: "[redacted]" if key.lower() in REDACT else redact_destination(item) if key == "destination_conf" else redact(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and value.startswith(('https://', 'http://')) and sensitive_webhook(value):
        from urllib.parse import urlsplit
        parsed = urlsplit(value)
        return f'{parsed.scheme}://{parsed.hostname}/[redacted destination]'
    return value


def redact_destination(value):
    """Keep the destination visible; credentials in its query/userinfo are secret."""
    if not isinstance(value, str):
        return redact(value)
    from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return "[redacted destination]"
        host = parts.netloc.rsplit("@", 1)[-1]
        safe_keys = {"region", "compression", "format", "output_type"}
        query = urlencode([(key, item if key.lower() in safe_keys else "[redacted]")
                           for key, item in parse_qsl(parts.query, keep_blank_values=True)])
        # Webhook credentials can also be embedded in the URL path.
        path = "/[redacted destination]" if parts.scheme in ("http", "https") and sensitive_webhook(value) else parts.path
        return urlunsplit((parts.scheme, host, path, query, ""))
    except ValueError:
        return "[redacted destination]"


def collect(client, root):
    import yaml
    account = root.name == "account"
    identity_file = root / ("account.yaml" if account else "domain.yaml")
    metadata = yaml.safe_load(identity_file.read_text(encoding="utf-8"))
    identity = metadata["account_id" if account else "zone_id"]
    observations, problems, runtime = {}, [], {}
    for service in services(account):
        path = endpoint(service, identity, account)
        try:
            value = client.pages(path) if service.collection else client.result(path)
            # List endpoints expose summaries; rules and memberships need their detail reads.
            if service.name == "other-rulesets":
                phases = {entry.endpoint.split('/')[2] for entry in services(account)
                          if entry.export and entry.endpoint.startswith('rulesets/phases/')}
                value = [item for item in value if not
                         (item.get('phase') in phases and item.get('kind') in ('zone', 'root'))
                         and item.get('kind') != 'managed']
                value = [client.result(f"/{'accounts' if account else 'zones'}/{identity}/rulesets/{item['id']}")
                         for item in value]
            elif service.name == "groups":
                value = [client.result(f"/accounts/{identity}/iam/user_groups/{group['id']}") for group in value]
                for group in value:
                    group["members"] = client.pages(f"/accounts/{identity}/iam/user_groups/{group['id']}/members")
            elif service.name == "lists":
                for item in value:
                    item["items"] = cursor_items(client, f"/accounts/{identity}/rules/lists/{item['id']}/items")
            if service.name == "email-settings":
                value = copy.deepcopy(value)
                runtime[service.name] = {key: value.pop(key) for key in ("modified", "synced") if key in value}
            if service.name == "dnssec" and value.get("status") in ("pending", "pending-disabled"):
                value = copy.deepcopy(value)
                runtime["dnssec"] = {"status": value["status"]}
                value["status"] = {"pending": "active", "pending-disabled": "disabled"}[value["status"]]
            if service.name == "certificate-packs":
                value = copy.deepcopy(value)
                runtime[service.name] = []
                for pack in value:
                    status = {"id": pack.get("id"), "status": pack.pop("status", None), "certificates": []}
                    for certificate in pack.get("certificates", []):
                        status["certificates"].append({"id": certificate.get("id"), "status": certificate.pop("status", None)})
                    runtime[service.name].append(status)
            if service.name == "zone-settings":
                for setting in value:
                    if setting.get("id") == "development_mode" and "time_remaining" in setting:
                        runtime["development-mode"] = {"time_remaining": setting["time_remaining"]}
            observations[service.name] = {"status": "ok", "value": canonical(value, unordered=service.collection),
                                          "files": list(service.files), "exportable": service.export}
        except UnavailableForPlan:
            observations[service.name] = {"status": "unavailable-plan", "files": list(service.files),
                                          "exportable": service.export}
        except SettingUnavailable:
            observations[service.name] = {"status": "unavailable-setting", "files": list(service.files),
                                          "exportable": service.export}
        except NotFound:
            # Keep this distinct from an authoritative successful empty response.
            observations[service.name] = {"status": "not-found", "files": list(service.files),
                                          "exportable": service.export}
        except (PermissionError, RuntimeError, ValueError, KeyError, TypeError) as error:
            observations[service.name] = {"status": "unreadable", "files": list(service.files),
                                          "exportable": service.export}
            problems.append(f"{service.name}: {type(error).__name__}; configuration was not fully read")
    if not account:
        catch = observations.get('email-catch-all', {})
        rules = observations.get('email-rules', {})
        if catch.get('status') == 'ok' and rules.get('status') == 'ok' and (catch.get('value') or {}).get('id'):
            catch_id = catch['value']['id']
            rules['value'] = [rule for rule in rules['value'] if rule.get('id') != catch_id]
        config = root / 'security/authenticated-origin-pulls.yaml'
        scope = yaml.safe_load(config.read_text(encoding='utf-8')) if config.exists() else None
        hostname = (scope or {}).get('hostname')
        if hostname:
            try:
                value = client.result(f'/zones/{identity}/origin_tls_client_auth/hostnames/{hostname}')
                observations['origin-pull-hostname'] = {'status': 'ok', 'value': canonical(value),
                                                       'files': [], 'exportable': True}
            except NotFound:
                observations['origin-pull-hostname'] = {'status': 'not-found', 'files': [], 'exportable': True}
            except (PermissionError, RuntimeError, ValueError, KeyError, TypeError):
                observations['origin-pull-hostname'] = {'status': 'unreadable', 'files': [], 'exportable': True}
                problems.append('origin-pull-hostname: configuration could not be read')
    payload = {"version": 1, "root": root.name, "identity": identity,
               "observations": observations, "problems": problems, "runtime": runtime}
    payload['limitations'] = ([
        'Registrar list responses do not reliably expose auto-renew, privacy, or a usable domain-name mapping.',
        'Webhook signing secrets are write-only; dashboard secret rotations cannot be detected from this inventory.',
    ] if account else ['Unconfigured hostname origin-pull associations cannot be enumerated by the endpoints used here.'])
    payload['limitations'].append('Configuration snapshots do not capture logs or changes reverted between observations.')
    payload['gaps'] = gaps(payload)
    payload["digest"] = digest({key: item for key, item in payload.items() if key not in ("problems", "runtime")})
    return payload


def cursor_items(client, path):
    items, cursor, seen = [], None, set()
    seen_ids = set()
    for _ in range(10000):
        params = {"per_page": 500}
        if cursor:
            params["cursor"] = cursor
        body = client.get(path, params)
        if not isinstance(body.get("result"), list):
            raise RuntimeError(f"{path}: invalid cursor response")
        for item in body['result']:
            identity = item.get('id') if isinstance(item, dict) else None
            if identity:
                if identity in seen_ids:
                    raise RuntimeError(f'{path}: overlapping object IDs during cursor pagination')
                seen_ids.add(identity)
        items.extend(body["result"])
        cursor = ((body.get("result_info") or {}).get("cursors") or {}).get("after")
        if not cursor:
            return canonical(items, unordered=True)
        if cursor in seen:
            raise RuntimeError(f"{path}: repeated cursor")
        seen.add(cursor)
    raise RuntimeError(f"{path}: cursor pagination did not terminate")


def record(snapshot):
    """Git stores configuration hashes and coverage, never a second copy of secrets."""
    return {"version": 1, "identity": snapshot["identity"], "observations": {
        name: {"status": item["status"], "digest": digest(item), "exportable": item["exportable"]}
        for name, item in snapshot["observations"].items()}}


def differences(snapshot, baseline):
    current = record(snapshot)
    before = (baseline or {}).get("observations", {})
    return [name for name in sorted(set(before) | set(current["observations"]))
            if before.get(name) != current["observations"].get(name)]


def require_complete(snapshot):
    if snapshot["problems"]:
        raise RuntimeError("Incomplete Cloudflare inventory: " + "; ".join(snapshot["problems"]))


def unresolved(snapshot):
    """Observation-only objects remain visible without triggering repeated exports."""
    return [name for name, item in snapshot['observations'].items()
            if item['status'] == 'ok' and not item['exportable'] and item.get('value')]


def gaps(snapshot):
    result = [f'{name}: observation-only configuration' for name in unresolved(snapshot)]
    result.extend(f'{name}: Cloudflare explicitly reports this setting unavailable for the zone plan'
                  for name, item in snapshot['observations'].items() if item['status'] == 'unavailable-plan')
    result.extend(f'{name}: Cloudflare denies access to the add-on setting; its value cannot be observed or managed'
                  for name, item in snapshot['observations'].items() if item['status'] == 'unavailable-setting')
    result.extend(f'{identity}: unsupported fields {fields}' for identity, fields in protected_objects(snapshot).items())
    dns = snapshot['observations'].get('dns', {})
    if dns.get('status') == 'ok':
        result.extend(f"DNS {item.get('id')}: unsupported record type {item.get('type')}"
                      for item in dns['value'] if item.get('type') not in ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'CAA', 'SRV'))
    return result


def protected_objects(snapshot):
    """Fields a whole-object API update would silently discard are deployment blockers."""
    protected = {}
    for name, observation in snapshot["observations"].items():
        if observation["status"] != "ok":
            continue
        value = observation.get("value")
        if name == "dns":
            for record in value:
                unsupported = [field for field in ("tags", "private_routing") if record.get(field)]
                if any(record.get("settings", {}).values()):
                    unsupported.append("settings")
                if unsupported:
                    protected[str(record["id"])] = unsupported
        elif isinstance(value, dict) and "rules" in value:
            dropped = []
            for rule in value.get("rules", []):
                clean(rule, RULE_SCHEMA, "rule", dropped)
                if name == "custom-waf":
                    dropped.extend("action_parameters." + field for field in
                                   set(rule.get("action_parameters") or {}) - {"ruleset", "phases", "products", "response"})
                if name == "rate-limits":
                    dropped.extend("ratelimit." + field for field in
                                   ("score_per_period", "score_response_header_name") if rule.get("ratelimit", {}).get(field))
            if dropped and value.get("id"):
                protected[str(value["id"])] = sorted(set(dropped))
        elif name in ("email-rules", "email-catch-all"):
            for rule in value if isinstance(value, list) else [value]:
                if rule.get("source") == "wrangler" or rule.get("owner_worker_tag"):
                    protected[str(rule["id"])] = ["Worker-managed routing ownership"]
        elif name == 'logpush':
            for job in value:
                fields = [key for key in ('output_options', 'max_upload_bytes', 'max_upload_interval_seconds', 'max_upload_records') if job.get(key)]
                if fields:
                    protected[str(job['id'])] = fields
        elif name == 'turnstile':
            for widget in value:
                fields = [key for key in ('offlabel', 'ephemeral_id') if widget.get(key)]
                if widget.get('clearance_level', 'no_clearance') != 'no_clearance':
                    fields.append('clearance_level')
                if fields:
                    protected[str(widget['sitekey'])] = fields
    return protected


def require_preserved(snapshot, plan):
    protected = protected_objects(snapshot)
    for resource in plan.get("resource_changes", []):
        change = resource["change"]
        if change["actions"] in (["no-op"], ["read"], ['delete']):
            continue
        if resource.get('type') == 'cloudflare_registrar_domain':
            raise RuntimeError('Registrar changes cannot be verified with this inventory API; production deployment is blocked rather than assuming unobserved settings')
        identity = str((change.get("before") or {}).get("id", ""))
        matches = [fields for object_id, fields in protected.items() if identity == object_id or identity.endswith("/" + object_id)]
        if matches:
            raise RuntimeError(f"{resource['address']} contains unsupported configuration {matches[0]}; preserve it before deploying")


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                          encoding="utf-8", newline="\n")
