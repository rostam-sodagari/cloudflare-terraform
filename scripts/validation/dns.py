"""DNS records: A/AAAA/CNAME/MX/TXT/NS, SPF, DMARC, DKIM, CAA, SRV, DNSSEC,
and the cross-file CNAME-conflict/duplicate-record checks."""
import base64
import binascii
import re

from yamlio import line_for, unquote_txt

from config import DKIM_MIN_RSA_BITS, EMAIL_RE, KEY_RE, NAME_RE
from .common import (
    Ctx, check_enum, check_fields, check_host, check_ttl, check_type,
    dkim_tags, is_cidr, is_ip, load, rsa_key_bits, list_values,
)

REC_FIELDS = {"name": "str", "content": "str", "proxied": "bool", "ttl": "int", "comment": "str", "priority": "int",
              "quoted": "bool"}


def txt_text(ctx, path, value):
    """Check TXT quoting and return the text inside the quotes (or None)."""
    if not isinstance(value, str):
        return None
    plain, quoted = unquote_txt(value)
    if quoted is None:
        ctx.error(path, "this starts with a double quote but is not a list of quoted strings.",
                  'write the text without quotes (they are added for you), or as "part one" "part two"')
        return None
    if quoted is False and '"' in value:
        ctx.error(path, "text contains a double quote.", 'write it as "..." with each inner quote as \\"')
        return None
    if quoted:
        for part in re.findall(r'"((?:[^"\\]|\\.)*)"', value):
            if len(part) > 255:
                ctx.error(path, "a quoted string is longer than 255 characters.",
                          "split it into several quoted strings, or remove the quotes and they are split for you")
    return plain


def validate_dns(report, d, plan, zone):
    """Validate DNS files in their established diagnostic discovery order."""
    domain_dir = d
    records = _validate_base_records(report, domain_dir, plan, zone)
    _validate_spf(report, domain_dir, plan, zone, records)
    _validate_dmarc(report, domain_dir, plan)
    _validate_dkim(report, domain_dir, plan)
    _validate_caa(report, domain_dir, plan)
    _validate_srv(report, domain_dir, plan)
    _validate_dnssec(report, domain_dir, plan)
    _validate_email_routing(report, domain_dir, plan)
    _check_record_conflicts(report, records, zone)


def _validate_base_records(report, domain_dir, plan, zone):
    records = []  # (fqdn, type, content, file, key, lines)

    for file_kind, record_type in [("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME"), ("mx", "MX"), ("txt", "TXT"), ("ns", "NS")]:
        config_file = domain_dir / "dns" / f"{file_kind}.yaml"
        data, line_numbers = load(report, config_file)
        if data in (None, "ERROR"):
            continue
        ctx = Ctx(report, config_file, line_numbers, plan)
        if not check_type(ctx, (), data, "dict"):
            continue
        fields = dict(REC_FIELDS)
        if record_type != "MX":
            fields.pop("priority")
        if record_type != "TXT":
            fields.pop("quoted")
        if record_type not in ("A", "AAAA", "CNAME"):
            fields.pop("proxied")
        for record_key, record in data.items():
            checked_record = _validate_record(ctx, record_key, record, fields, record_type, zone)
            if checked_record is not None:
                records.append(checked_record)
    return records


def _fqdn(record_name, zone):
    record_name = str(record_name)
    if record_name in ("@", zone):
        return zone
    return record_name if record_name.endswith("." + zone) else f"{record_name}.{zone}"


def _validate_record(ctx, record_key, record, fields, record_type, zone):
    record_path = (record_key,)
    if not KEY_RE.match(str(record_key)):
        ctx.error(record_path, f"key '{record_key}' contains characters that are not allowed.", "use letters, digits, _ - . or @")
    if record is None:
        ctx.error(record_path, f"'{record_key}' has no fields.", "add at least name and content")
        return None
    if not check_fields(ctx, record_path, record, fields, required=["content"] + (["priority"] if record_type == "MX" else [])):
        return None
    record_name = record.get("name", record_key)
    if isinstance(record_name, str) and not NAME_RE.match(record_name):
        ctx.error(record_path + ("name",), f"'{record_name}' is not a valid record name.",
                  'use "@" for the apex, a label like "www", or a full name without a trailing dot')
    content = record.get("content")
    if not isinstance(content, str):
        return None
    if record_type == "A" and not is_ip(content, 4):
        ctx.error(record_path + ("content",), f"'{content}' is not an IPv4 address.", "AAAA records go in aaaa.yaml")
    if record_type == "AAAA" and not is_ip(content, 6):
        ctx.error(record_path + ("content",), f"'{content}' is not an IPv6 address.", "A records go in a.yaml")
    if record_type in ("CNAME", "MX", "NS"):
        check_host(ctx, record_path + ("content",), content)
    if record_type == "MX" and isinstance(record.get("priority"), int) and not (0 <= record["priority"] <= 65535):
        ctx.error(record_path + ("priority",), "MX priority must be 0 to 65535.")
    if record_type == "NS" and str(record_name) in ("@", zone):
        ctx.error(record_path + ("name",), "apex NS records are managed by Cloudflare.", "ns.yaml is for delegating a subdomain")
    if record_type == "TXT":
        content = txt_text(ctx, record_path + ("content",), content) or ""
        if content.startswith("v=spf1"):
            ctx.error(record_path + ("content",), "SPF record found in txt.yaml.", "move it to spf.yaml")
        if content.startswith("v=DMARC1"):
            ctx.error(record_path + ("content",), "DMARC record found in txt.yaml.", "move it to dmarc.yaml")
        if len(content) > 2048:
            ctx.error(record_path + ("content",), "TXT content is longer than 2048 characters.")
    if record.get("proxied") is True and isinstance(record.get("ttl"), int) and record["ttl"] != 1:
        ctx.warn(record_path + ("ttl",), "ttl is ignored for proxied records (Cloudflare uses automatic).", "remove ttl")
    if record_type == "CNAME" and isinstance(record_name, str) and _fqdn(content, zone) == _fqdn(record_name, zone):
        ctx.error(record_path + ("content",), "CNAME points to itself.")
    check_ttl(ctx, record_path + ("ttl",), record.get("ttl"), ctx.plan)
    if isinstance(record.get("comment"), str) and len(record["comment"]) > (100 if ctx.plan == "free" else 500):
        ctx.error(record_path + ("comment",), "comment is too long for this plan (Free 100, paid 500 characters).")
    return (_fqdn(record_name, zone).lower(), record_type, content, ctx.file, record_key, ctx.lines)


def _validate_spf(report, domain_dir, plan, zone, records):
    config_file = domain_dir / "dns" / "spf.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, plan)
    fields = {"includes": "list", "ip4": "list", "ip6": "list", "a": "bool", "mx": "bool", "extra": "list",
            "all": "str", "raw": "str", "ttl": "int", "comment": "str", "quoted": "bool"}
    if not check_type(ctx, (), data, "dict"):
        return
    for hostname, spf_config in data.items():
        record_path = (hostname,)
        if spf_config is None:
            spf_config = {}
        if not check_fields(ctx, record_path, spf_config, fields):
            continue
        check_enum(ctx, record_path + ("all",), spf_config.get("all"), ["-all", "~all", "?all", "+all"])
        if spf_config.get("all") == "+all":
            ctx.flag("spf_not_plus_all", record_path + ("all",), "+all lets anyone send mail as this domain.", 'use "-all" or "~all"')
        for item_index, ip_range in enumerate(list_values(spf_config.get("ip4"))):
            if not is_cidr(str(ip_range), 4):
                ctx.error(record_path + ("ip4", item_index), f"'{ip_range}' is not an IPv4 address or range.")
        for item_index, ip_range in enumerate(list_values(spf_config.get("ip6"))):
            if not is_cidr(str(ip_range), 6):
                ctx.error(record_path + ("ip6", item_index), f"'{ip_range}' is not an IPv6 address or range.")
        for item_index, include_domain in enumerate(list_values(spf_config.get("includes"))):
            check_host(ctx, record_path + ("includes", item_index), str(include_domain).removeprefix("include:"), "domain")
            if str(include_domain).startswith("include:"):
                ctx.error(record_path + ("includes", item_index), "write only the domain; 'include:' is added for you.")
        raw_content = txt_text(ctx, record_path + ("raw",), spf_config.get("raw")) if spf_config.get("raw") else None
        if raw_content:
            if not raw_content.startswith("v=spf1"):
                ctx.error(record_path + ("raw",), "raw SPF must start with v=spf1.")
            if any(field_name in spf_config for field_name in ("includes", "ip4", "ip6", "a", "mx", "extra")):
                ctx.warn(record_path + ("raw",), "raw is set, so the other fields are ignored.")
            content = raw_content
        else:
            content_parts = ["v=spf1"] + (["a"] if spf_config.get("a") else []) + (["mx"] if spf_config.get("mx") else [])
            content_parts += [f"ip4:{value}" for value in list_values(spf_config.get("ip4"))] + [f"ip6:{value}" for value in list_values(spf_config.get("ip6"))]
            content_parts += [f"include:{value}" for value in list_values(spf_config.get("includes"))] + list(list_values(spf_config.get("extra")))
            content_parts.append(spf_config.get("all", "-all"))
            content = " ".join(map(str, content_parts))
        lookup_count = len([mechanism for mechanism in content.split()
                       if re.match(r"^[-~?+]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr|exists:|redirect=)", mechanism)])
        if lookup_count > 10:
            ctx.error(record_path, f"this SPF needs {lookup_count} DNS lookups; the limit is 10 (RFC 7208), so receivers will reject it.",
                      "remove senders you no longer use, or replace includes with ip4 ranges")
        check_ttl(ctx, record_path + ("ttl",), spf_config.get("ttl"), plan)
        records.append(((zone if hostname == "@" else f"{hostname}.{zone}").lower(), "TXT", content, config_file, hostname, line_numbers))


def _validate_dmarc(report, domain_dir, plan):
    config_file = domain_dir / "dns" / "dmarc.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, plan)
    fields = {"policy": "str", "subdomain_policy": "str", "pct": "int", "rua": "list", "ruf": "list",
            "adkim": "str", "aspf": "str", "fo": "str", "raw": "str", "ttl": "int", "comment": "str", "quoted": "bool"}
    if not check_type(ctx, (), data, "dict"):
        return
    for hostname, dmarc_config in data.items():
        dmarc_config = {} if dmarc_config is None else dmarc_config
        record_path = (hostname,)
        if not check_fields(ctx, record_path, dmarc_config or {}, fields):
            continue
        dmarc_config = dmarc_config or {}
        check_enum(ctx, record_path + ("policy",), dmarc_config.get("policy"), ["none", "quarantine", "reject"])
        check_enum(ctx, record_path + ("subdomain_policy",), dmarc_config.get("subdomain_policy"), ["none", "quarantine", "reject"])
        check_enum(ctx, record_path + ("adkim",), dmarc_config.get("adkim"), ["r", "s"])
        check_enum(ctx, record_path + ("aspf",), dmarc_config.get("aspf"), ["r", "s"])
        if isinstance(dmarc_config.get("pct"), int) and not (0 <= dmarc_config["pct"] <= 100):
            ctx.error(record_path + ("pct",), "pct must be 0 to 100.")
        for field_name in ("rua", "ruf"):
            for address_index, email_address in enumerate(list_values(dmarc_config.get(field_name))):
                if not EMAIL_RE.match(str(email_address)):
                    ctx.error(record_path + (field_name, address_index), f"'{email_address}' is not an e-mail address.")
        if dmarc_config.get("raw") and not (txt_text(ctx, record_path + ("raw",), dmarc_config["raw"]) or "").startswith("v=DMARC1"):
            ctx.error(record_path + ("raw",), "raw DMARC must start with v=DMARC1.")
        if not dmarc_config.get("raw") and not dmarc_config.get("rua"):
            ctx.flag("dmarc_has_rua", record_path, "no rua address, so you will not receive DMARC reports.", "add rua: [dmarc@yourdomain]")
        if not dmarc_config.get("raw") and dmarc_config.get("policy") == "none":
            ctx.flag("dmarc_policy_strict", record_path + ("policy",),
                     "policy is 'none', so DMARC is monitoring only -- spoofed mail is not actually rejected or quarantined yet.",
                     'move to "quarantine" then "reject" once the rua reports look clean')
        check_ttl(ctx, record_path + ("ttl",), dmarc_config.get("ttl"), plan)


def _validate_dkim(report, domain_dir, plan):
    config_file = domain_dir / "dns" / "dkim.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, plan)
    if not check_type(ctx, (), data, "dict"):
        return
    for selector, dkim_config in data.items():
        record_path = (selector,)
        if not check_fields(ctx, record_path, dkim_config or {},
                            {"content": "str", "name": "str", "ttl": "int", "comment": "str", "quoted": "bool"},
                            ["content"]):
            continue
        record_name = dkim_config.get("name")
        if isinstance(record_name, str):
            check_host(ctx, record_path + ("name",), record_name)
            if "_domainkey" not in record_name:
                ctx.error(record_path + ("name",), f"'{record_name}' does not contain _domainkey.",
                          'use "<selector>._domainkey" or "<selector>._domainkey.<subdomain>"')
        if isinstance(dkim_config.get("content"), str):
            plain_content = txt_text(ctx, record_path + ("content",), dkim_config["content"]) or ""
            if "p=" not in plain_content:
                ctx.flag("dkim_looks_valid", record_path + ("content",), "this does not look like a DKIM key (no p= tag).")
            else:
                tags = dkim_tags(plain_content)
                if tags.get("k", "rsa") == "rsa" and tags.get("p"):
                    try:
                        der_bytes = base64.b64decode(tags["p"], validate=False)
                    except (binascii.Error, ValueError):
                        der_bytes = b""
                    key_bits = rsa_key_bits(der_bytes) if der_bytes else None
                    if key_bits is not None and key_bits < DKIM_MIN_RSA_BITS:
                        ctx.flag("dkim_key_size_strong", record_path + ("content",),
                                 f"this DKIM key is {key_bits}-bit RSA; weaker than the recommended {DKIM_MIN_RSA_BITS}.",
                                 f"ask your mail provider for a {DKIM_MIN_RSA_BITS}-bit (or larger) DKIM key")
        check_ttl(ctx, record_path + ("ttl",), dkim_config.get("ttl"), plan)


def _validate_caa(report, domain_dir, plan):
    config_file = domain_dir / "dns" / "caa.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, plan)
    fields = {"name": "str", "flags": "int", "tag": "str", "value": "str", "ttl": "int", "comment": "str"}
    if not check_type(ctx, (), data, "dict"):
        return
    allowed_authorities = set()
    for record_key, caa_config in data.items():
        record_path = (record_key,)
        if not check_fields(ctx, record_path, caa_config or {}, fields, ["tag", "value"]):
            continue
        check_enum(ctx, record_path + ("tag",), caa_config.get("tag"), ["issue", "issuewild", "iodef"])
        check_enum(ctx, record_path + ("flags",), caa_config.get("flags"), [0, 128])
        authority = caa_config.get("value")
        if isinstance(authority, str) and caa_config.get("tag") in ("issue", "issuewild"):
            allowed_authorities.add(authority.split(";", 1)[0].strip().lower())
        check_ttl(ctx, record_path + ("ttl",), caa_config.get("ttl"), plan)
    if data and not ({"letsencrypt.org", "pki.goog", "ssl.com"} & allowed_authorities):
        ctx.flag("caa_trusted_ca", (), "CAA records do not explicitly allow a Cloudflare Universal SSL issuer.",
                 "check effective DNS CAA, including Cloudflare's automatically added records, before relying on certificate renewal")


def _validate_srv(report, domain_dir, plan):
    config_file = domain_dir / "dns" / "srv.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, plan)
    fields = {"name": "str", "priority": "int", "weight": "int", "port": "int", "target": "str", "ttl": "int", "comment": "str"}
    if not check_type(ctx, (), data, "dict"):
        return
    for record_key, srv_config in data.items():
        record_path = (record_key,)
        if not check_fields(ctx, record_path, srv_config or {}, fields, ["name", "priority", "weight", "port", "target"]):
            continue
        if isinstance(srv_config.get("name"), str) and not re.match(r"^_[A-Za-z0-9-]+\._(tcp|udp|tls)(\.|$)", srv_config["name"]):
            ctx.error(record_path + ("name",), f"'{srv_config['name']}' is not an SRV name.", "format: _service._tcp (or ._udp / ._tls)")
        for field_name, maximum in (("priority", 65535), ("weight", 65535), ("port", 65535)):
            if isinstance(srv_config.get(field_name), int) and not (0 <= srv_config[field_name] <= maximum):
                ctx.error(record_path + (field_name,), f"{field_name} must be 0 to {maximum}.")
        if isinstance(srv_config.get("target"), str):
            check_host(ctx, record_path + ("target",), srv_config["target"])


def _validate_dnssec(report, domain_dir, plan):
    config_file = domain_dir / "dns" / "dnssec.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, plan)
    if check_fields(ctx, (), data, {"status": "str"}, ["status"]):
        check_enum(ctx, ("status",), data.get("status"), ["active", "disabled"])


def _validate_email_routing(report, domain_dir, plan):
    config_file = domain_dir / "dns" / "email-routing.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, plan)
    if check_fields(ctx, (), data, {"enabled": "bool", "support_subaddress": "bool",
                                    "rules": "list", "catch_all": "dict"}, ["enabled"]):
        seen_rule_refs = set()
        if data.get("support_subaddress") is not None:
            ctx.error(("support_subaddress",), "the pinned provider cannot apply support_subaddress; configure it in Cloudflare and omit this field.")
        for rule_index, rule in enumerate(list_values(data.get("rules"))):
            rule = {} if rule is None else rule
            record_path = ("rules", rule_index)
            if not check_fields(ctx, record_path, rule or {}, {"ref": "str", "name": "str", "enabled": "bool", "priority": "int",
                                                   "matchers": "list", "actions": "list"},
                                ["ref", "matchers", "actions"]):
                continue
            rule_ref = rule.get("ref")
            if not isinstance(rule_ref, str):
                continue
            if rule_ref in seen_rule_refs:
                ctx.error(record_path + ("ref",), f"ref '{rule['ref']}' is used twice.")
            seen_rule_refs.add(rule_ref)
            for entry_index, matcher in enumerate(list_values(rule.get("matchers"))):
                matcher_path = record_path + ("matchers", entry_index)
                if check_fields(ctx, matcher_path, matcher or {}, {"field": "str", "type": "str", "value": "str"}, ["type"]):
                    check_enum(ctx, matcher_path + ("type",), matcher.get("type"), ["all", "literal"])
                    if matcher.get("type") == "literal":
                        for field in ("field", "value"):
                            if not matcher.get(field):
                                ctx.error(matcher_path + (field,), f"{field} is required for literal matchers.")
            for entry_index, action in enumerate(list_values(rule.get("actions"))):
                action = {} if action is None else action
                if check_fields(ctx, record_path + ("actions", entry_index), action or {}, {"type": "str", "value": "list"}, ["type"]):
                    check_enum(ctx, record_path + ("actions", entry_index, "type"), action.get("type"), ["forward", "worker", "drop"])
                    if action.get("type") in ("forward", "worker") and not action.get("value"):
                        ctx.error(record_path + ("actions", entry_index, "value"), "value is required for forward or worker actions.")
                    for destination_index, destination in enumerate(list_values(action.get("value"))):
                        check_type(ctx, record_path + ("actions", entry_index, "value", destination_index), destination, "str")
        catch_all = data.get("catch_all")
        if catch_all is not None:
            if check_fields(ctx, ("catch_all",), catch_all, {"action": "str", "destination": "str", "enabled": "bool", "name": "str"}, ["action"]):
                check_enum(ctx, ("catch_all", "action"), catch_all.get("action"), ["forward", "worker", "drop"])
                if catch_all.get("action") in ("forward", "worker") and not catch_all.get("destination"):
                    ctx.error(("catch_all", "destination"), "destination is required when action is forward or worker.")


def _check_record_conflicts(report, records, zone):
    records_by_name = {}
    for record_fqdn, record_type, content, config_file, record_key, line_numbers in records:
        records_by_name.setdefault(record_fqdn, []).append((record_type, content, config_file, record_key, line_numbers))
    for record_fqdn, matching_records in records_by_name.items():
        record_types = {record_type for record_type, *_ in matching_records}
        # Cloudflare flattens a CNAME at the zone apex (serves it as A/AAAA),
        # which is exactly why MX/TXT/NS can coexist with a root CNAME --
        # the usual "CNAME excludes everything else" DNS rule only applies
        # below the apex.
        if "CNAME" in record_types and len(matching_records) > 1 and record_fqdn != zone:
            record_type, content, config_file, record_key, line_numbers = [record for record in matching_records if record[0] == "CNAME"][0]
            others = ", ".join(sorted(f"{other_record[0]} in {other_record[2].name}" for other_record in matching_records if other_record[3] != record_key or other_record[2] != config_file))
            report.add("error", config_file, line_for(line_numbers, (record_key,)), f"{record_fqdn} has a CNAME and other records ({others}).",
                       "a name with a CNAME cannot have any other record")
        seen_records = {}
        for record_type, content, config_file, record_key, line_numbers in matching_records:
            record_identity = (record_type, content)
            if record_identity in seen_records:
                report.add("error", config_file, line_for(line_numbers, (record_key,)),
                           f"duplicate {record_type} record {record_fqdn} -> {content} (also '{seen_records[record_identity][1]}' in {seen_records[record_identity][0].name}).",
                           "remove one of them")
            seen_records[record_identity] = (config_file, record_key)
