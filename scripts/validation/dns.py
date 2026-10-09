"""DNS records: A/AAAA/CNAME/MX/TXT/NS, SPF, DMARC, DKIM, CAA, SRV, DNSSEC,
and the cross-file CNAME-conflict/duplicate-record checks."""
import base64
import binascii
import re

from yamlio import line_for, unquote_txt

from config import DKIM_MIN_RSA_BITS

from .common import (
    Ctx, EMAIL_RE, KEY_RE, NAME_RE, check_enum, check_fields, check_host,
    check_record_doc_blocks, check_ttl, check_type, dkim_tags, is_cidr,
    is_ip, load, rsa_key_bits,
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
    records = []  # (fqdn, type, content, file, key, lines)

    def fqdn(name):
        name = str(name)
        if name in ("@", zone):
            return zone
        return name if name.endswith("." + zone) else f"{name}.{zone}"

    for kind, rtype in [("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME"), ("mx", "MX"), ("txt", "TXT"), ("ns", "NS")]:
        f = d / "dns" / f"{kind}.yaml"
        data, lines = load(report, f)
        if data in (None, "ERROR"):
            continue
        ctx = Ctx(report, f, lines, plan)
        if not check_type(ctx, (), data, "dict"):
            continue
        check_record_doc_blocks(ctx, f, data, needs_proxy=rtype in ("A", "AAAA", "CNAME"))
        fields = dict(REC_FIELDS)
        if rtype != "MX":
            fields.pop("priority")
        if rtype != "TXT":
            fields.pop("quoted")
        if rtype not in ("A", "AAAA", "CNAME"):
            fields.pop("proxied")
        for key, r in data.items():
            p = (key,)
            if not KEY_RE.match(str(key)):
                ctx.error(p, f"key '{key}' contains characters that are not allowed.", "use letters, digits, _ - . or @")
            if r is None:
                ctx.error(p, f"'{key}' has no fields.", "add at least name and content")
                continue
            if not check_fields(ctx, p, r, fields, required=["content"] + (["priority"] if rtype == "MX" else [])):
                continue
            name = r.get("name", key)
            if isinstance(name, str) and not NAME_RE.match(name):
                ctx.error(p + ("name",), f"'{name}' is not a valid record name.",
                          'use "@" for the apex, a label like "www", or a full name without a trailing dot')
            c = r.get("content")
            if not isinstance(c, str):
                continue
            if rtype == "A" and not is_ip(c, 4):
                ctx.error(p + ("content",), f"'{c}' is not an IPv4 address.", "AAAA records go in aaaa.yaml")
            if rtype == "AAAA" and not is_ip(c, 6):
                ctx.error(p + ("content",), f"'{c}' is not an IPv6 address.", "A records go in a.yaml")
            if rtype in ("CNAME", "MX", "NS"):
                check_host(ctx, p + ("content",), c)
            if rtype == "MX" and isinstance(r.get("priority"), int) and not (0 <= r["priority"] <= 65535):
                ctx.error(p + ("priority",), "MX priority must be 0 to 65535.")
            if rtype == "NS" and str(name) in ("@", zone):
                ctx.error(p + ("name",), "apex NS records are managed by Cloudflare.", "ns.yaml is for delegating a subdomain")
            if rtype == "TXT":
                c = txt_text(ctx, p + ("content",), c) or ""
                if c.startswith("v=spf1"):
                    ctx.error(p + ("content",), "SPF record found in txt.yaml.", "move it to spf.yaml")
                if c.startswith("v=DMARC1"):
                    ctx.error(p + ("content",), "DMARC record found in txt.yaml.", "move it to dmarc.yaml")
                if len(c) > 2048:
                    ctx.error(p + ("content",), "TXT content is longer than 2048 characters.")
            if r.get("proxied") is True and isinstance(r.get("ttl"), int) and r["ttl"] != 1:
                ctx.warn(p + ("ttl",), "ttl is ignored for proxied records (Cloudflare uses automatic).", "remove ttl")
            if rtype == "CNAME" and isinstance(name, str) and fqdn(c) == fqdn(name):
                ctx.error(p + ("content",), "CNAME points to itself.")
            check_ttl(ctx, p + ("ttl",), r.get("ttl"), plan)
            if isinstance(r.get("comment"), str) and len(r["comment"]) > (100 if plan == "free" else 500):
                ctx.error(p + ("comment",), "comment is too long for this plan (Free 100, paid 500 characters).")
            records.append((fqdn(name).lower(), rtype, c, f, key, lines))

    # SPF
    f = d / "dns" / "spf.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"includes": "list", "ip4": "list", "ip6": "list", "a": "bool", "mx": "bool", "extra": "list",
                "all": "str", "raw": "str", "ttl": "int", "comment": "str", "quoted": "bool"}
        if check_type(ctx, (), data, "dict"):
            check_record_doc_blocks(ctx, f, data)
            for host, s in data.items():
                p = (host,)
                if s is None:
                    s = {}
                if not check_fields(ctx, p, s, spec):
                    continue
                check_enum(ctx, p + ("all",), s.get("all"), ["-all", "~all", "?all", "+all"])
                if s.get("all") == "+all":
                    ctx.flag("spf_not_plus_all", p + ("all",), "+all lets anyone send mail as this domain.", 'use "-all" or "~all"')
                for i, ip in enumerate(s.get("ip4") or []):
                    if not is_cidr(str(ip), 4):
                        ctx.error(p + ("ip4", i), f"'{ip}' is not an IPv4 address or range.")
                for i, ip in enumerate(s.get("ip6") or []):
                    if not is_cidr(str(ip), 6):
                        ctx.error(p + ("ip6", i), f"'{ip}' is not an IPv6 address or range.")
                for i, inc in enumerate(s.get("includes") or []):
                    check_host(ctx, p + ("includes", i), str(inc).removeprefix("include:"), "domain")
                    if str(inc).startswith("include:"):
                        ctx.error(p + ("includes", i), "write only the domain; 'include:' is added for you.")
                raw = txt_text(ctx, p + ("raw",), s.get("raw")) if s.get("raw") else None
                if raw:
                    if not raw.startswith("v=spf1"):
                        ctx.error(p + ("raw",), "raw SPF must start with v=spf1.")
                    if any(k in s for k in ("includes", "ip4", "ip6", "a", "mx", "extra")):
                        ctx.warn(p + ("raw",), "raw is set, so the other fields are ignored.")
                    content = raw
                else:
                    parts = ["v=spf1"] + (["a"] if s.get("a") else []) + (["mx"] if s.get("mx") else [])
                    parts += [f"ip4:{x}" for x in s.get("ip4") or []] + [f"ip6:{x}" for x in s.get("ip6") or []]
                    parts += [f"include:{x}" for x in s.get("includes") or []] + list(s.get("extra") or [])
                    parts.append(s.get("all", "-all"))
                    content = " ".join(map(str, parts))
                lookups = len([t for t in content.split()
                               if re.match(r"^[-~?+]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr|exists:|redirect=)", t)])
                if lookups > 10:
                    ctx.error(p, f"this SPF needs {lookups} DNS lookups; the limit is 10 (RFC 7208), so receivers will reject it.",
                              "remove senders you no longer use, or replace includes with ip4 ranges")
                check_ttl(ctx, p + ("ttl",), s.get("ttl"), plan)
                records.append(((zone if host == "@" else f"{host}.{zone}").lower(), "TXT", content, f, host, lines))

    # DMARC
    f = d / "dns" / "dmarc.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"policy": "str", "subdomain_policy": "str", "pct": "int", "rua": "list", "ruf": "list",
                "adkim": "str", "aspf": "str", "fo": "str", "raw": "str", "ttl": "int", "comment": "str", "quoted": "bool"}
        if check_type(ctx, (), data, "dict"):
            check_record_doc_blocks(ctx, f, data)
            for host, m in data.items():
                p = (host,)
                if not check_fields(ctx, p, m or {}, spec):
                    continue
                m = m or {}
                check_enum(ctx, p + ("policy",), m.get("policy"), ["none", "quarantine", "reject"])
                check_enum(ctx, p + ("subdomain_policy",), m.get("subdomain_policy"), ["none", "quarantine", "reject"])
                check_enum(ctx, p + ("adkim",), m.get("adkim"), ["r", "s"])
                check_enum(ctx, p + ("aspf",), m.get("aspf"), ["r", "s"])
                if isinstance(m.get("pct"), int) and not (0 <= m["pct"] <= 100):
                    ctx.error(p + ("pct",), "pct must be 0 to 100.")
                for fld in ("rua", "ruf"):
                    for i, a in enumerate(m.get(fld) or []):
                        if not EMAIL_RE.match(str(a)):
                            ctx.error(p + (fld, i), f"'{a}' is not an e-mail address.")
                if m.get("raw") and not (txt_text(ctx, p + ("raw",), m["raw"]) or "").startswith("v=DMARC1"):
                    ctx.error(p + ("raw",), "raw DMARC must start with v=DMARC1.")
                if not m.get("raw") and not m.get("rua"):
                    ctx.flag("dmarc_has_rua", p, "no rua address, so you will not receive DMARC reports.", "add rua: [dmarc@yourdomain]")
                if not m.get("raw") and m.get("policy") == "none":
                    ctx.flag("dmarc_policy_strict", p + ("policy",),
                             "policy is 'none', so DMARC is monitoring only -- spoofed mail is not actually rejected or quarantined yet.",
                             'move to "quarantine" then "reject" once the rua reports look clean')
                check_ttl(ctx, p + ("ttl",), m.get("ttl"), plan)

    # DKIM
    f = d / "dns" / "dkim.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_type(ctx, (), data, "dict"):
            check_record_doc_blocks(ctx, f, data)
            for sel, k in data.items():
                p = (sel,)
                if not check_fields(ctx, p, k or {},
                                    {"content": "str", "name": "str", "ttl": "int", "comment": "str", "quoted": "bool"},
                                    ["content"]):
                    continue
                name = k.get("name")
                if isinstance(name, str):
                    check_host(ctx, p + ("name",), name)
                    if "_domainkey" not in name:
                        ctx.error(p + ("name",), f"'{name}' does not contain _domainkey.",
                                  'use "<selector>._domainkey" or "<selector>._domainkey.<subdomain>"')
                if isinstance(k.get("content"), str):
                    plain = txt_text(ctx, p + ("content",), k["content"]) or ""
                    if "p=" not in plain:
                        ctx.flag("dkim_looks_valid", p + ("content",), "this does not look like a DKIM key (no p= tag).")
                    else:
                        tags = dkim_tags(plain)
                        if tags.get("k", "rsa") == "rsa" and tags.get("p"):
                            try:
                                der = base64.b64decode(tags["p"], validate=False)
                            except (binascii.Error, ValueError):
                                der = b""
                            bits = rsa_key_bits(der) if der else None
                            if bits is not None and bits < DKIM_MIN_RSA_BITS:
                                ctx.flag("dkim_key_size_strong", p + ("content",),
                                         f"this DKIM key is {bits}-bit RSA; weaker than the recommended {DKIM_MIN_RSA_BITS}.",
                                         f"ask your mail provider for a {DKIM_MIN_RSA_BITS}-bit (or larger) DKIM key")
                check_ttl(ctx, p + ("ttl",), k.get("ttl"), plan)

    # CAA
    f = d / "dns" / "caa.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"name": "str", "flags": "int", "tag": "str", "value": "str", "ttl": "int", "comment": "str"}
        if check_type(ctx, (), data, "dict"):
            check_record_doc_blocks(ctx, f, data)
            tags = set()
            for key, c in data.items():
                p = (key,)
                if not check_fields(ctx, p, c or {}, spec, ["tag", "value"]):
                    continue
                check_enum(ctx, p + ("tag",), c.get("tag"), ["issue", "issuewild", "iodef"])
                check_enum(ctx, p + ("flags",), c.get("flags"), [0, 128])
                tags.add((c.get("value") or "").lower())
                check_ttl(ctx, p + ("ttl",), c.get("ttl"), plan)
            if data and not ({"letsencrypt.org", "pki.goog"} & tags):
                ctx.flag("caa_trusted_ca", (), "CAA records exist but neither letsencrypt.org nor pki.goog is allowed.",
                         "Cloudflare Universal SSL uses these CAs; without them edge certificates cannot renew")

    # SRV
    f = d / "dns" / "srv.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"name": "str", "priority": "int", "weight": "int", "port": "int", "target": "str", "ttl": "int", "comment": "str"}
        if check_type(ctx, (), data, "dict"):
            check_record_doc_blocks(ctx, f, data)
            for key, r in data.items():
                p = (key,)
                if not check_fields(ctx, p, r or {}, spec, ["name", "priority", "weight", "port", "target"]):
                    continue
                if isinstance(r.get("name"), str) and not re.match(r"^_[A-Za-z0-9-]+\._(tcp|udp|tls)(\.|$)", r["name"]):
                    ctx.error(p + ("name",), f"'{r['name']}' is not an SRV name.", "format: _service._tcp (or ._udp / ._tls)")
                for fld, hi in (("priority", 65535), ("weight", 65535), ("port", 65535)):
                    if isinstance(r.get(fld), int) and not (0 <= r[fld] <= hi):
                        ctx.error(p + (fld,), f"{fld} must be 0 to {hi}.")
                if isinstance(r.get("target"), str):
                    check_host(ctx, p + ("target",), r["target"])

    # DNSSEC
    f = d / "dns" / "dnssec.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"status": "str"}, ["status"]):
            check_enum(ctx, ("status",), data.get("status"), ["active", "disabled"])

    # Email routing
    f = d / "dns" / "email-routing.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"enabled": "bool", "support_subaddress": "bool",
                                        "rules": "list", "catch_all": "dict"}, ["enabled"]):
            seen_refs = set()
            for i, r in enumerate(data.get("rules") or []):
                p = ("rules", i)
                if not check_fields(ctx, p, r or {}, {"ref": "str", "name": "str", "enabled": "bool",
                                                       "matchers": "list", "actions": "list"},
                                    ["ref", "matchers", "actions"]):
                    continue
                if r["ref"] in seen_refs:
                    ctx.error(p + ("ref",), f"ref '{r['ref']}' is used twice.")
                seen_refs.add(r["ref"])
                for j, m in enumerate(r.get("matchers") or []):
                    check_fields(ctx, p + ("matchers", j), m or {}, {"field": "str", "type": "str", "value": "str"},
                                ["field", "type", "value"])
                for j, a in enumerate(r.get("actions") or []):
                    if check_fields(ctx, p + ("actions", j), a or {}, {"type": "str", "value": "list"}, ["type"]):
                        check_enum(ctx, p + ("actions", j, "type"), a.get("type"), ["forward", "worker", "drop"])
            ca = data.get("catch_all")
            if ca is not None:
                if check_fields(ctx, ("catch_all",), ca, {"action": "str", "destination": "str"}, ["action"]):
                    check_enum(ctx, ("catch_all", "action"), ca.get("action"), ["forward", "worker", "drop"])
                    if ca.get("action") == "forward" and not ca.get("destination"):
                        ctx.error(("catch_all", "destination"), "destination is required when action is forward.")

    # Cross-file: CNAME conflicts and duplicates
    by_name = {}
    for fq, t, c, f, key, lines in records:
        by_name.setdefault(fq, []).append((t, c, f, key, lines))
    for fq, recs in by_name.items():
        types = {t for t, *_ in recs}
        # Cloudflare flattens a CNAME at the zone apex (serves it as A/AAAA),
        # which is exactly why MX/TXT/NS can coexist with a root CNAME --
        # the usual "CNAME excludes everything else" DNS rule only applies
        # below the apex.
        if "CNAME" in types and len(recs) > 1 and fq != zone:
            t, c, f, key, lines = [r for r in recs if r[0] == "CNAME"][0]
            others = ", ".join(sorted(f"{x[0]} in {x[2].name}" for x in recs if x[3] != key or x[2] != f))
            report.add("error", f, line_for(lines, (key,)), f"{fq} has a CNAME and other records ({others}).",
                       "a name with a CNAME cannot have any other record")
        seen = {}
        for t, c, f, key, lines in recs:
            sig = (t, c)
            if sig in seen:
                report.add("error", f, line_for(lines, (key,)),
                           f"duplicate {t} record {fq} -> {c} (also '{seen[sig][1]}' in {seen[sig][0].name}).",
                           "remove one of them")
            seen[sig] = (f, key)
