"""Review actual API differences alongside Terraform's managed resource plan."""
import copy
from .inventory import collect, canonical, require_complete, redact, save
from .coverage import services
from .semantics import require_valid_plan, resources, writable, state_only
from .lifecycle import stops_managing, STATE_ONLY_DELETE


SERVICE_BY_TYPE = {
    "dns_record": "dns", "zone_dnssec": "dnssec", "zone_setting": "zone-settings",
    "bot_management": "bots", "access_rule": "access", "email_routing_settings": "email-settings",
    "email_routing_rule": "email-rules", "email_routing_catch_all": "email-catch-all",
    "total_tls": "total-tls", "ct_alerting": "ct-alerting", "authenticated_origin_pulls_settings": "origin-pulls",
    "authenticated_origin_pulls": "origin-pull-hostname", "certificate_pack": "certificate-packs",
    "zone_cache_variants": "cache-variants", "tiered_cache": "smart-tiered",
    "argo_tiered_caching": "argo-tiered", "zone_cache_reserve": "cache-reserve",
    "argo_smart_routing": "argo-routing", "regional_tiered_cache": "regional-tiered",
    "origin_ca_certificate": "origin-certificates", "list": "lists", "logpush_job": "logpush",
    "notification_policy": "notifications", "notification_policy_webhooks": "webhooks",
    "registrar_domain": "registrar", "sso_connector": "sso", "user_group": "groups",
    "user_group_members": "groups", "account_dns_settings": "account-dns", "turnstile_widget": "turnstile",
}


def service_for(resource, account):
    if resource["type"] == "cloudflare_ruleset":
        value = resource["change"].get("after") or resource["change"].get("before") or {}
        endpoint = f"rulesets/phases/{value.get('phase')}/entrypoint"
        matches = [service.name for service in services(account) if service.endpoint == endpoint]
        if len(matches) != 1:
            raise RuntimeError(f"No exact API verification contract for {resource['address']}")
        return matches[0]
    try:
        return SERVICE_BY_TYPE[resource["type"].removeprefix("cloudflare_")]
    except KeyError:
        raise RuntimeError(f"No API verification contract for {resource['type']}") from None


def snapshot(client, root, plan):
    value = collect(client, root)
    require_complete(value)
    if value.get("runtime", {}).get("dnssec"):
        status = value["runtime"]["dnssec"]["status"]
        print(f"DNSSEC operational status: {status}. Check the DS record at your registrar; this workflow does not change registrar DS records.")
    if value.get("runtime", {}).get("development-mode"):
        seconds = value["runtime"]["development-mode"]["time_remaining"]
        print(f"Development Mode expiry countdown: {seconds} seconds (runtime status, retained in the inventory).")
    for pack in value.get("runtime", {}).get("certificate-packs", []):
        if pack.get("status") not in (None, "active"):
            print(f"Certificate pack {pack['id']} operational status: {pack['status']} (retained in the inventory).")
    routing = [resource for resource in plan.get("resource_changes", [])
               if resource["type"] == "cloudflare_email_routing_settings" and any(
                   action in resource["change"]["actions"] for action in ("create", "delete"))]
    if routing:
        records = client.pages(f"/zones/{value['identity']}/email/routing/dns")
        if not records or any(not all(record.get(key) for key in ("type", "name", "content")) or
                              record["type"] not in ("MX", "TXT") for record in records):
            raise RuntimeError("Email Routing DNS effects cannot be determined; no changes applied")
        value["email_dns_records"] = canonical(records, unordered=True)
    return value


def require_compatible(plan, inventory):
    """Do not route known provider failures into an unnecessary live write."""
    require_valid_plan(plan)
    groups = inventory["observations"].get("groups", {}).get("value") or []
    for resource in plan.get("resource_changes", []):
        change = resource["change"]
        resource_type = resource["type"]
        if resource.get("mode") == "data" or (change["actions"] in (["no-op"], ["read"]) and not change.get("importing")):
            continue
        service = service_for(resource, inventory["root"] == "account")
        availability = inventory["observations"].get(service, {}).get("status")
        if availability in ("unavailable-plan", "unavailable-setting"):
            raise RuntimeError(f"{resource['address']}: Cloudflare reports this setting unavailable for the zone plan or add-on access; no changes applied")
        if resource_type == "cloudflare_bot_management" and any(action in change["actions"] for action in ("create", "update")):
            bots = inventory["observations"].get("bots", {}).get("value") or {}
            if any(field in bots for field in ("ai_search", "ai_training", "ai_user", "bot_preference_sync_enabled")):
                raise RuntimeError("Cloudflare provider 5.27.0 mixes legacy and modern AI bot preferences in its update request. Live testing confirmed inconsistent values and extra preference changes. Bot Management writes on migrated zones require a verified provider fix; no changes applied.")
        for values in (change.get("before"), change.get("after")):
            scope = (values or {}).get("account_id" if inventory["root"] == "account" else "zone_id")
            if scope and scope != inventory["identity"]:
                raise RuntimeError(f"{resource['address']}: changing zone/account scope needs separate inventories and state migration; no changes applied")
            if resource_type == "cloudflare_origin_ca_certificate" and values:
                hostnames = values.get("hostnames") or []
                zone_name = inventory["root"].lower()
                if not hostnames or any(not isinstance(hostname, str) or
                        not (hostname.lower() == zone_name or hostname.lower().endswith("." + zone_name))
                        for hostname in hostnames):
                    raise RuntimeError(f"{resource['address']}: Origin CA certificates must cover only this zone; other zones need separate inventories and review.")
        if resource_type in STATE_ONLY_DELETE and "delete" in change["actions"] and "create" in change["actions"]:
            raise RuntimeError(f"{resource['address']}: provider replacement leaves the previous dashboard setting intact. Use separate reviewed operations to stop managing it and manage the new setting.")
        if resource_type == "cloudflare_account_dns_settings" and (change.get("importing") or "create" in change["actions"]):
            raise RuntimeError("Cloudflare provider 5.27.0 cannot import existing account DNS settings. Adoption requires a verified provider fix; an API update is not a state-only import.")
        if resource_type == "cloudflare_authenticated_origin_pulls" and change.get("importing"):
            raise RuntimeError("Cloudflare provider 5.27.0 does not populate hostname origin-pull config on import. Adoption requires a verified provider fix.")
        if resource_type == "cloudflare_notification_policy_webhooks":
            previous = (change.get("before") or {}).get("secret")
            desired = (change.get("after") or {}).get("secret")
            if desired != previous or (change.get("after_unknown") or {}).get("secret"):
                raise RuntimeError(f"{resource['address']}: webhook signing secrets are write-only. Their value cannot be verified from the dashboard API; this operation needs a separate verification procedure.")
        if resource_type == "cloudflare_user_group_members":
            configured = (change.get("after") or change.get("before") or {}).get("members") or []
            group_id = (change.get("before") or change.get("after") or {}).get("user_group_id")
            live = next((group.get("members", []) for group in groups if group["id"] == group_id), [])
            if len(configured) > 100 or len(live) > 100:
                raise RuntimeError("Cloudflare provider 5.27.0 reads only one membership page. This group requires a verified pagination fix; no membership changes applied.")
    setting_side_effects(plan, inventory)


def setting_side_effects(plan, inventory):
    """Expose and verify Cloudflare's two API views of TLS session resumption."""
    settings = {item["id"]: item.get("value") for item in
                inventory["observations"].get("zone-settings", {}).get("value", [])}
    changes = {}
    for resource in plan.get("resource_changes", []):
        change = resource["change"]
        if resource["type"] != "cloudflare_zone_setting" or change["actions"] in (["no-op"], ["read"], ["delete"]):
            continue
        after = change.get("after") or {}
        setting = after.get("setting_id")
        if setting in ("0rtt", "tls_1_3"):
            changes[setting] = after.get("value")
    if len(changes) > 1:
        raise RuntimeError("0rtt and tls_1_3 control the same Cloudflare feature; use one Terraform writer and review its secondary effect.")
    effects = []
    for setting, value in changes.items():
        alias = "0rtt" if setting == "tls_1_3" else "tls_1_3"
        desired = ("on" if value == "zrt" else "off") if alias == "0rtt" else (
            "zrt" if value == "on" else "off" if settings.get(alias) == "off" else "on")
        if alias not in settings or value not in (("on", "off", "zrt") if setting == "tls_1_3" else ("on", "off")):
            raise RuntimeError("Cannot determine TLS secondary effects; no changes applied")
        for resource in plan.get("resource_changes", []):
            after = resource["change"].get("after") or {}
            if resource["type"] == "cloudflare_zone_setting" and after.get("setting_id") == alias and after.get("value") != desired:
                raise RuntimeError("0rtt and tls_1_3 control the same Cloudflare feature; configure consistent values and use one writer.")
        if settings[alias] != desired:
            effects.append({"setting": alias, "before": settings[alias], "after": desired})
    return effects


def preview_setting_effects(plan, inventory):
    effects = setting_side_effects(plan, inventory)
    if not effects:
        return ""
    preview = "Cloudflare also changes these linked settings:\n" + "\n".join(
        f"  {item['setting']}: {item['before']} -> {item['after']}" for item in effects)
    print(preview)
    return preview


def prepare(root, run_tf):
    import os
    import json
    from exporting.client import Client
    plan = json.loads((root.dir / "plan.json").read_text(encoding="utf-8"))
    reviewed = json.loads((root.dir / ".local-inventory.json").read_text(encoding="utf-8"))
    client = Client(os.environ["CLOUDFLARE_API_TOKEN"])
    current = snapshot(client, root.dir, plan)
    if current["observations"] != reviewed["observations"] or current.get("email_dns_records") != reviewed.get("email_dns_records"):
        raise RuntimeError("Cloudflare changed after planning. Run plan again before applying.")
    require_compatible(plan, current)
    preview_setting_effects(plan, current)
    from .inventory import require_preserved
    require_preserved(current, plan)
    # A new plan detects changes to state and provider-observed fields too.
    result = run_tf([f"-chdir={root.dir}", "plan", "-input=false", "-lock-timeout=60s", "-out=.local-preflight.bin"], capture=True)
    (root.dir / ".local-preflight.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout + result.stderr)
    try:
        if result.returncode:
            raise RuntimeError("Local deployment preflight failed; run plan again")
        result = run_tf([f"-chdir={root.dir}", "show", "-json", ".local-preflight.bin"], capture=True)
        if result.returncode:
            raise RuntimeError("Cannot read local deployment preflight")
        fresh = json.loads(result.stdout)
        require_valid_plan(fresh)
        schema = read_schema(root, run_tf)
        from .rules_validation import validate_rulesets
        validate_rulesets(client, fresh, schema, current)
        from .semantics import effects
        if effects(fresh, schema) != effects(plan, schema):
            raise RuntimeError("Terraform effects changed after planning. Run plan again.")
    finally:
        (root.dir / ".local-preflight.bin").unlink(missing_ok=True)
    return {"client": client, "before": reviewed, "plan": plan, "schema": schema}


def recheck(root, context):
    """Confirmation can take time; re-read immediately before the write starts."""
    current = snapshot(context["client"], root.dir, context["plan"])
    if current["observations"] != context["before"]["observations"] or current.get("email_dns_records") != context["before"].get("email_dns_records"):
        raise RuntimeError("Cloudflare changed while awaiting confirmation. Run plan again.")


def read_schema(root, run_tf):
    import json
    result = run_tf([f"-chdir={root.dir}", "providers", "schema", "-json"], capture=True)
    if result.returncode:
        raise RuntimeError("Cannot read provider schema for dashboard verification")
    return json.loads(result.stdout)


def finish(root, directory, context, run_tf):
    import json
    after, issues = None, []
    try:
        after = snapshot(context["client"], root.dir, context["plan"])
        result = run_tf([f"-chdir={root.dir}", "show", "-json"], capture=True)
        if result.returncode:
            raise RuntimeError("Cannot read resulting Terraform state")
        issues.extend(verify(context["before"], after, context["plan"], context["schema"], json.loads(result.stdout)))
        result = run_tf([f"-chdir={root.dir}", "plan", "-input=false", "-lock-timeout=60s", "-out=.local-verify.bin"], capture=True)
        (directory / "verify.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        print(result.stdout + result.stderr)
        if result.returncode:
            issues.append("Terraform follow-up plan failed")
        else:
            result = run_tf([f"-chdir={root.dir}", "show", "-json", ".local-verify.bin"], capture=True)
            if result.returncode or not state_only(json.loads(result.stdout)):
                issues.append("Terraform still has pending changes")
        final = snapshot(context["client"], root.dir, context["plan"])
        if final["observations"] != after["observations"] or final.get("email_dns_records") != after.get("email_dns_records"):
            issues.append("Cloudflare changed during post-apply verification")
    except (RuntimeError, ValueError, OSError, KeyError, TypeError) as error:
        issues.append(str(error))
    finally:
        (root.dir / ".local-verify.bin").unlink(missing_ok=True)
        report(directory, context["before"], after, issues)
    if issues:
        raise RuntimeError("Dashboard verification failed: " + "; ".join(issues) + f". Review {directory}; do not blindly repeat apply.")


def failed(root, directory, context):
    """Capture actual partial effects even when Terraform exits unsuccessfully."""
    after = None
    issues = ["Terraform apply failed; changes may have partially succeeded. Reconcile state and dashboard before a new plan."]
    try:
        after = snapshot(context["client"], root.dir, context["plan"])
    except (RuntimeError, ValueError, OSError, KeyError, TypeError) as error:
        issues.append(str(error))
    report(directory, context["before"], after, issues)


def _identity(value, resource_type):
    if resource_type == "cloudflare_zone_setting":
        return value.get("setting_id") or value.get("id")
    if resource_type == "cloudflare_user_group_members":
        return value.get("user_group_id") or value.get("id")
    return value.get("id") or value.get("sitekey") or value.get("hostname")


def _object(observation, identity, resource_type):
    if observation.get("status") != "ok":
        return None
    value = observation.get("value")
    if isinstance(value, list):
        matches = [item for item in value if str(_identity(item, resource_type)) == str(identity)]
        if len(matches) > 1:
            raise RuntimeError("Ambiguous API identity; cannot verify deployment")
        return matches[0] if matches else None
    return value


def _view(value, attributes):
    """Compare writable fields; API-only fields are checked in the residual inventory."""
    if not isinstance(value, dict):
        return value
    if "requests_to_origin" in attributes and "characteristics" in attributes:
        # Cloudflare omits false: counting cached requests is the API default.
        value = {"requests_to_origin": False, **value}
    if "dnssec_multi_signer" in attributes and value.get("status") in ("pending", "pending-disabled"):
        value = {**value, "status": {"pending": "active", "pending-disabled": "disabled"}[value["status"]]}
    if "include_shadow_metadata" in attributes and value.get("type") in ("A", "AAAA", "CNAME"):
        # The DNS API omits disabled flags that the provider expands to false.
        settings = {"flatten_cname": False, "ipv4_only": False, "ipv6_only": False,
                    **(value.get("settings") or {})}
        value = {**value, "settings": settings}
    if "config" in attributes and value.get("hostname") and "config" not in value:
        value = {**value, "config": [{key: value.get(key) for key in ("hostname", "enabled", "cert_id")}]}
    result = {}
    for key, spec in attributes.items():
        if not (spec.get("optional") or spec.get("required")) or key not in value:
            continue
        item = value[key]
        nested = spec.get("nested_type")
        if nested and item is not None:
            if isinstance(item, dict):
                item = _view(item, nested["attributes"]) if nested["nesting_mode"] == "single" else {
                    name: _view(entry, nested["attributes"]) for name, entry in item.items()}
            elif isinstance(item, list):
                item = [_view(entry, nested["attributes"]) for entry in item]
        if item is not None:
            result[key] = item
    return canonical(result)


def _dns_planned_values(value):
    """Structured data determines content; provider plans can retain old text."""
    import json
    data = value.get("data") or {}
    record_type = value.get("type")
    if record_type in ("A", "AAAA", "CNAME") and isinstance(value.get("settings"), dict):
        settings = {**value["settings"]}
        for key in ("flatten_cname", "ipv4_only", "ipv6_only"):
            if settings.get(key) is None:
                settings[key] = False
        value = {**value, "settings": settings}
    if record_type == "CAA" and all(data.get(key) is not None for key in ("flags", "tag", "value")):
        return {**value, "content": f'{data["flags"]:g} {data["tag"]} {json.dumps(data["value"], ensure_ascii=False)}'}
    if record_type == "SRV" and all(data.get(key) is not None for key in ("weight", "port", "target")):
        return {**value, "content": f'{data["weight"]:g} {data["port"]:g} {data["target"]}'}
    return value


def _known_matches(actual, desired, unknown):
    if unknown is True:
        return True
    if isinstance(desired, dict):
        actual = actual if isinstance(actual, dict) else {}
        return all(_known_matches(actual.get(key), item, unknown.get(key, False) if isinstance(unknown, dict) else False)
                   for key, item in desired.items())
    if isinstance(desired, list):
        return isinstance(actual, list) and len(actual) == len(desired) and all(
            _known_matches(left, right, unknown[index] if isinstance(unknown, list) and index < len(unknown) else False)
            for index, (left, right) in enumerate(zip(actual, desired)))
    return actual in (None, "", [], {}) if desired is None else actual == desired


def verify(before, after, plan, provider_schema, state):
    require_valid_plan(plan)
    remaining_before, remaining_after = copy.deepcopy(before["observations"]), copy.deepcopy(after["observations"])
    state_values = {resource["address"]: resource.get("values") or {} for resource in
                    resources(state.get("values", {}).get("root_module", {}))}
    issues = []
    aliases = {item["setting"]: item["after"] for item in setting_side_effects(plan, before)}
    for setting, desired in aliases.items():
        original = next(item for item in before["observations"]["zone-settings"]["value"] if item["id"] == setting)
        actual = next((item for item in after["observations"].get("zone-settings", {}).get("value", []) if item["id"] == setting), None)
        if actual != {**original, "value": desired}:
            issues.append(f"{setting}: linked setting does not match the reviewed secondary effect")
        for item in remaining_before["zone-settings"]["value"]:
            if item["id"] == setting:
                item["value"] = desired
    if aliases:
        remaining_before["zone-settings"]["value"] = canonical(remaining_before["zone-settings"]["value"], unordered=True)
    for resource in plan.get("resource_changes", []):
        change = resource["change"]
        if resource.get("mode") == "data" or change["actions"] in (["no-op"], ["read"]):
            continue
        service = service_for(resource, before.get("root") == "account")
        old = change.get("before") or {}
        new = state_values.get(resource["address"], change.get("after") or {})
        left_observation = remaining_before.get(service, {"status": "not-found"})
        right_observation = remaining_after.get(service, {"status": "not-found"})
        left = _object(before["observations"].get(service, {}), _identity(old, resource["type"]), resource["type"])
        right = _object(after["observations"].get(service, {}), _identity(new or old, resource["type"]), resource["type"])
        attributes = provider_schema["provider_schemas"][resource["provider_name"]]["resource_schemas"][resource["type"]]["block"]["attributes"]
        if stops_managing(resource):
            expected = {**left, "value": aliases[left["id"]]} if left and left.get("id") in aliases and service == "zone-settings" else left
            if expected != right:
                issues.append(f"{resource['address']}: dashboard changed during a state-only removal")
            continue
        if change["actions"] == ["delete"]:
            # Deleting membership empties the group rather than deleting it.
            if resource["type"] == "cloudflare_user_group_members":
                if right and right.get("members"):
                    issues.append(f"{resource['address']}: group members were not removed")
                residual_group = _object(left_observation, _identity(old, resource["type"]), resource["type"])
                if residual_group:
                    residual_group["members"] = []
                continue
            if right is not None and service != "email-settings":
                issues.append(f"{resource['address']}: object still exists after deletion")
            if service == "email-settings" and (right or {}).get("enabled") is not False:
                issues.append(f"{resource['address']}: Email Routing remains enabled")
        elif right is None:
            issues.append(f"{resource['address']}: expected object is missing")
        else:
            wanted = writable(change.get("after") or {}, attributes)
            planned_before = writable(old, attributes)
            if resource["type"] == "cloudflare_dns_record":
                wanted = _dns_planned_values(wanted)
                planned_before = _dns_planned_values(planned_before)
            wanted = {key: item for key, item in wanted.items() if key not in
                      ("zone_id", "account_id", "user_group_id", "setting_id", "page", "per_page", "direction", "fuzzy_email", "include_shadow_metadata", "ownership_challenge", "secret")
                      and (item is not None or planned_before.get(key) is not None)}
            if not _known_matches(_view(right, attributes), wanted, change.get("after_unknown", {})):
                issues.append(f"{resource['address']}: dashboard does not match the planned values")
            # Every unplanned writable field must retain its prior API value.
            old_view, new_view = _view(left or {}, attributes), _view(right, attributes)
            for key in set(old_view) | set(new_view):
                if old_view.get(key) != new_view.get(key) and planned_before.get(key) == wanted.get(key) and not (change.get("after_unknown") or {}).get(key):
                    issues.append(f"{resource['address']}: unplanned change to {key}")
            if service == "email-settings" and "create" in change["actions"] and right.get("enabled") is not True:
                issues.append(f"{resource['address']}: Email Routing was not enabled")
        # Remove the matched object from residual comparison. API-only fields
        # on updated objects must remain unchanged as well.
        if left is not None and right is not None and change["actions"] != ["delete"]:
            computed = {key for key, spec in attributes.items() if spec.get("computed") and not spec.get("optional")}
            ignored = set(attributes) | computed
            if service == "groups":
                for other in plan.get("resource_changes", []):
                    values = other["change"].get("before") or state_values.get(other["address"], {})
                    if other["type"] in ("cloudflare_user_group", "cloudflare_user_group_members") and other["change"]["actions"] != ["no-op"] and _identity(values, other["type"]) == _identity(new or old, resource["type"]):
                        ignored.update(provider_schema["provider_schemas"][other["provider_name"]]["resource_schemas"][other["type"]]["block"]["attributes"])
            if {key: item for key, item in left.items() if key not in ignored} != {key: item for key, item in right.items() if key not in ignored}:
                issues.append(f"{resource['address']}: API-only fields changed")
        for observation, item in ((left_observation, left), (right_observation, right)):
            if isinstance(observation.get("value"), list):
                if item is not None and item in observation["value"]:
                    observation["value"].remove(item)
            elif item is not None:
                observation["value"] = None
        # Treat an absent singleton and a deleted singleton alike.
        if left_observation.get("value") in (None, [], {}) and right_observation.get("value") in (None, [], {}):
            remaining_before.pop(service, None)
            remaining_after.pop(service, None)
    if before.get("email_dns_records"):
        issues.extend(_verify_email_dns(remaining_before, remaining_after, before, plan))
    for service in set(remaining_before) | set(remaining_after):
        if remaining_before.get(service) != remaining_after.get(service):
            issues.append(f"{service}: dashboard changes outside the planned objects")
    return sorted(set(issues))


def _verify_email_dns(left, right, baseline, plan):
    issues = []
    for resource in plan.get("resource_changes", []):
        if resource["type"] != "cloudflare_email_routing_settings":
            continue
        adding = "create" in resource["change"]["actions"]
        deleting = "delete" in resource["change"]["actions"]
        if not adding and not deleting:
            continue
        for expected in baseline["email_dns_records"]:
            if deleting and expected["type"] != "MX":
                continue
            expected = dict(expected)
            if expected["name"] == "@":
                expected["name"] = baseline["root"]
            def matches(record):
                return all(record.get(key) == item for key, item in expected.items() if item is not None)
            previous = [item for item in left.get("dns", {}).get("value", []) if matches(item)]
            current = [item for item in right.get("dns", {}).get("value", []) if matches(item)]
            if len(previous) > 1 or len(current) > 1 or (adding and len(current) != 1) or (deleting and current):
                issues.append(f"Email Routing: unexpected DNS outcome for {expected['type']} {expected['name']}")
            for observation, items in ((left, previous), (right, current)):
                for item in items:
                    observation["dns"]["value"].remove(item)
    return issues


def report(directory, before, after, issues):
    save(directory / "dashboard-outcome.json", {"issues": issues, "before": redact(before), "after": redact(after)})
