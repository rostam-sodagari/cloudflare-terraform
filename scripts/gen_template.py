#!/usr/bin/env python3
"""
Write the documentation headers for every file in domains/_template.

The template files are the single source of the per-file instructions:
`python3 cf.py new` copies them and the exporter puts each header above
exported data. Edit the text here and run:

    python3 scripts/gen_template.py

Every example in a header is commented out, so a new domain changes nothing
until someone removes the # in front of the lines they want. Each header is
a short summary with one example; the full field-by-field reference lives
in docs/20-services.md.

To also refresh the instructions in existing domains (their data is kept):

    python3 scripts/gen_template.py domains/example.com domains/example.net
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
T = ROOT / "domains" / "_template"

CHECK = """#
# Check: python3 cf.py validate <domain> — or just open the pull request; CI runs the same check."""

KEYS = """#
# The key before the colon (e.g. "www:") is this item's permanent ID.
# Change the fields under it freely; renaming the key deletes and recreates it."""

DNS_COMMON = """#
# name     "@" for the domain itself, or a label such as www or mail. No trailing dot.
# ttl      Seconds; leave out for automatic (recommended). 60-86400 (30 on Enterprise). Ignored when proxied.
# comment  Optional note kept alongside the record in Cloudflare."""

RULES = """#
# FORMAT: ref (unique id), description, expression (when it runs — Cloudflare's
# rules language, e.g. http.request.uri.path eq "/x", starts_with(...), ip.src
# in {...}, combined with and/or), action_parameters (what it does), optional
# enabled: false. Don't add "action:".
# Rules run top to bottom. Regex (matches, ~, regex_replace) needs Business+.
# Limits: Free 10, Pro 25, Business 50, Enterprise 300 rules in this file."""

REF = """#
# Full field reference: docs/20-services.md"""


def header(title, body, keys=False, dns=False, rules=False, ref=True):
    parts = ["# " + "=" * 75, f"# {title}", "# " + "=" * 75, body.rstrip()]
    if keys:
        parts.append(KEYS)
    if dns:
        parts.append(DNS_COMMON)
    if rules:
        parts.append(RULES)
    if ref:
        parts.append(REF)
    return "\n".join(parts)


FILES = {
"domain.yaml": header("domain.yaml: which Cloudflare zone this folder controls (REQUIRED)", """#
#   name      The domain exactly as shown in Cloudflare, e.g. example.com. Must match the folder name.
#   zone_id   Zone Overview page > API section > Zone ID (32 hex characters). Keep the quotes.
#   plan      free | pro | business | enterprise — must match the real plan.
#   owner     Team responsible for this domain (for people; not used by Terraform).
#   example   Only for this repo's sample folders; never set it on a real domain.""", ref=False) + "\n" + CHECK + """
name: DOMAIN_NAME
zone_id: "ZONE_ID"
plan: free
owner: change-me
""",

"dns/a.yaml": header("dns/a.yaml: A records (name -> IPv4 address)", """#
#   content  IPv4 address, e.g. 203.0.113.10.
#   proxied  true = Cloudflare proxy (CDN/WAF, hides your origin) — use for websites.
#            false = DNS only — use for mail, VPN, SSH. Leave out for false.""", keys=True, dns=True) + """
#
# CAREFUL: changing content moves traffic to a new server.
#
# EXAMPLE (remove the # to use):
# root:
#   name: "@"
#   content: 203.0.113.10
#   proxied: true
""" + CHECK + "\n",

"dns/aaaa.yaml": header("dns/aaaa.yaml: AAAA records (name -> IPv6 address)", """#
#   content  IPv6 address, e.g. 2001:db8::10.
#   proxied  As in a.yaml: true for websites, false for everything else.""", keys=True, dns=True) + """
#
# EXAMPLE:
# root_v6:
#   name: "@"
#   content: 2001:db8::10
#   proxied: true
""" + CHECK + "\n",

"dns/cname.yaml": header("dns/cname.yaml: CNAME records (name -> another hostname)", """#
#   content  Target hostname, e.g. myapp.herokuapp.com. No https://, path or trailing dot.
#   proxied  true for websites, false for everything else.
#
# A name with a CNAME cannot have any other record (no A, MX or TXT with the same name).
# Microsoft 365 DKIM uses CNAMEs — put those here, not in dkim.yaml.""", keys=True, dns=True) + """
#
# EXAMPLE:
# www:
#   name: www
#   content: example.com
#   proxied: true
""" + CHECK + "\n",

"dns/mx.yaml": header("dns/mx.yaml: MX records (where e-mail for the domain is delivered)", """#
#   content   Mail server hostname, from your mail provider.
#   priority  Required. Lower number is tried first.
#
# CAREFUL: removing or mistyping an MX record stops e-mail from arriving.""", keys=True, dns=True) + """
#
# EXAMPLE:
# m365:
#   name: "@"
#   content: example-com.mail.protection.outlook.com
#   priority: 0
""" + CHECK + "\n",

"dns/txt.yaml": header("dns/txt.yaml: TXT records (site verifications and other text)", """#
#   content  The exact text you were given, e.g. google-site-verification=abc.
#
# SPF, DMARC and DKIM have their own files — the check rejects them here.
# Quoting: write plain text; Cloudflare's quotes are added for you. See docs/10-yaml-basics.md.""", keys=True, dns=True) + """
#
# EXAMPLE:
# google_verification:
#   name: "@"
#   content: google-site-verification=abc123
""" + CHECK + "\n",

"dns/ns.yaml": header("dns/ns.yaml: NS records (hand a SUBDOMAIN to other name servers)", """#
#   content  The other DNS provider's name server.
#
# Only for subdomains — the domain's own NS records belong to Cloudflare.""", keys=True, dns=True) + """
#
# EXAMPLE (dev.example.com answered by another provider):
# dev_1:
#   name: dev
#   content: ns1.other-dns.example
""" + CHECK + "\n",

"dns/spf.yaml": header("dns/spf.yaml: SPF (which servers may send e-mail as this domain)", """#
# One entry per name ("@" for the domain itself, or a label like mail).
#   includes  Domains that send for you, e.g. spf.protection.outlook.com (no "include:").
#   ip4/ip6   Your own mail server addresses or ranges.
#   a / mx    true to allow the domain's A or MX hosts.
#   all       "-all" reject (default) | "~all" mark as suspicious.
#   raw       Complete SPF text instead of the fields above.
#   quoted    false only for an old unquoted record.
#
# The check fails if more than 10 DNS lookups are needed (RFC 7208).""") + """
#
# EXAMPLE:
# "@":
#   includes: [spf.protection.outlook.com, _spf.google.com]
#   ip4: [203.0.113.0/28]
#   all: "-all"
""" + CHECK + "\n",

"dns/dmarc.yaml": header("dns/dmarc.yaml: DMARC (what receivers do with mail that fails SPF/DKIM)", """#
# Published at _dmarc.<name>. The key is "@" for the domain itself.
#   policy   none (monitor) | quarantine (spam) | reject
#   rua      Addresses that receive daily summary reports.
#   raw      Complete DMARC text instead of the fields above.
#
# SAFE ROLLOUT: start with policy: none and an rua address, then tighten.""") + """
#
# EXAMPLE:
# "@":
#   policy: none
#   rua: [dmarc-reports@example.com]
""" + CHECK + "\n",

"dns/dkim.yaml": header("dns/dkim.yaml: DKIM keys published as TXT records", """#
# The key is the selector your mail provider gives you; published at <selector>._domainkey.
#   content  The full key text from your mail provider (starts v=DKIM1).
#   name     Optional override of the published name. Only needed when the
#            selector itself contains a dot (e.g. "select1.343"), or when
#            DKIM is published under a subdomain, not the zone apex (e.g.
#            Mailgun's "mta._domainkey.mg"). Leave it out for the common
#            case; it defaults to "<selector>._domainkey".
#
# Microsoft 365 DKIM uses CNAME records instead: put those in cname.yaml.""") + """
#
# EXAMPLES:
# google:
#   content: v=DKIM1; k=rsa; p=MIIBIjANBgkqh...
# mailgun:
#   name: mta._domainkey.mg
#   content: v=DKIM1; k=rsa; p=MIIBIjANBgkqh...
""" + CHECK + "\n",

"dns/caa.yaml": header("dns/caa.yaml: CAA records (which certificate authorities may issue)", """#
#   tag    issue (certificates) | issuewild (wildcards) | iodef (report address)
#   value  The CA's domain, e.g. letsencrypt.org, or mailto:... for iodef.
#
# CAREFUL: once any CAA record exists, ONLY the listed CAs may issue. Keep
# letsencrypt.org and pki.goog or Cloudflare's own certificates can't renew.""", keys=True) + """
#
# EXAMPLE:
# letsencrypt:
#   tag: issue
#   value: letsencrypt.org
""" + CHECK + "\n",

"dns/srv.yaml": header("dns/srv.yaml: SRV records (service discovery, e.g. Teams, SIP)", """#
#   name      _service._protocol, e.g. _sip._tls
#   priority, weight, port, target   all required, from the service's setup guide""", keys=True) + """
#
# EXAMPLE:
# m365_sip:
#   name: _sip._tls
#   priority: 100
#   weight: 1
#   port: 443
#   target: sipdir.online.lync.com
""" + CHECK + "\n",

"dns/dnssec.yaml": header("dns/dnssec.yaml: DNSSEC (signs DNS answers)", """#
#   status  active | disabled
#
# TURNING ON: status: active, merge, then add the DS record (Terraform
# output dnssec_ds) at the domain registrar.
#
# TURNING OFF (order matters): remove the DS record at the registrar, wait
# 24 to 48 hours, then status: disabled. Never just delete this file once
# DNSSEC is managed — the plan refuses to, to protect against doing this
# out of order.""") + """
#
# status: active
""" + CHECK + "\n",

"waf/custom-rules.yaml": header("waf/custom-rules.yaml: WAF custom rules (block, challenge or allow traffic)", """#
#   ref, description, expression, action (block | managed_challenge | js_challenge
#   | challenge | skip | log — log is Enterprise only), optional enabled: false.
#   response:  optional, paid plans, action block only — a custom block page.
#   skip:      only with action: skip — what to skip (ruleset/phases/products).
#
# Rules run top to bottom: put "skip" (allow) rules first.
# Limits: Free 5, Pro 20, Business 100, Enterprise 1000. Regex needs Business+.""") + """
#
# EXAMPLES:
# - ref: allow_monitoring
#   description: Uptime monitor skips the remaining custom rules
#   expression: (ip.src in {198.51.100.10 198.51.100.11})
#   action: skip
#   skip:
#     ruleset: current
#
# - ref: block_admin_outside_uk
#   description: Admin only from the UK and Ireland
#   expression: (starts_with(http.request.uri.path, "/admin") and not ip.src.country in {"GB" "IE"})
#   action: block
""" + CHECK + "\n",

"waf/rate-limits.yaml": header("waf/rate-limits.yaml: rate limiting (too many requests from one visitor)", """#
#   ref, description, expression   as in custom-rules.yaml
#   requests_per_period   Required. Requests allowed per `period` seconds:
#                         10, 60, 120, 300, 600, 3600.
#   mitigation_timeout    Seconds blocked: 0, 10, 60, 120, 300, 600, 3600, 86400.
#   action                block (default) | managed_challenge | js_challenge | challenge
#   characteristics       Default [ip.src, cf.colo.id]; must include cf.colo.id.
#
# Per plan: Free 1 rule, Pro 2, Business 5, Enterprise 100 — full table in docs/20-services.md.""") + """
#
# EXAMPLE:
# - ref: login_rl
#   description: Login brute force
#   expression: (http.request.uri.path eq "/login" and http.request.method eq "POST")
#   period: 60
#   requests_per_period: 10
#   mitigation_timeout: 600
""" + CHECK + "\n",

"waf/managed-rules.yaml": header("waf/managed-rules.yaml: Cloudflare's managed WAF rulesets (Pro and above)", """#
# On Free, Cloudflare applies its own Free Managed Ruleset: leave this file commented.
#
#   cloudflare_managed: { enabled, action }        common attacks, CVEs
#   owasp: { enabled, paranoia_level 1-4, score_threshold 60|40|25, action }
#   exceptions: [{ ref, description, expression, rulesets }]   skip a ruleset for matching traffic
#
# "log" action is Enterprise only. raw_rules: (written by the exporter) replaces
# the simple form entirely when present.
#
# CAREFUL: emptying this file after it has been applied DELETES the managed WAF protection.""") + """
#
# EXAMPLE:
# cloudflare_managed:
#   enabled: true
# owasp:
#   enabled: true
#   score_threshold: 60
#   action: managed_challenge
""" + CHECK + "\n",

"security/hsts.yaml": header("security/hsts.yaml: HSTS (browsers must always use HTTPS)", """#
#   enabled, max_age (seconds; start at 300, raise to 31536000 once confident),
#   include_subdomains, preload (needs include_subdomains + max_age 31536000), nosniff.
#
# CAREFUL: browsers enforce HTTPS for max_age even after you switch it off.
# preload is very hard to undo.""") + """
#
# enabled: true
# max_age: 300
# include_subdomains: false
# preload: false
# nosniff: true
""" + CHECK + "\n",

"security/bot-management.yaml": header("security/bot-management.yaml: bot protection", """#
# Available settings depend on the plan; the check tells you if you use one your plan lacks.
#   Free         fight_mode
#   Pro/Business sbfm_definitely_automated, sbfm_likely_automated (Business), sbfm_verified_bots,
#                sbfm_static_resource_protection, optimize_wordpress, enable_js
#   All plans    ai_bots_protection, crawler_protection, is_robots_txt_managed
#   Enterprise   auto_update_model, suppress_session_score
#
# CAREFUL: blocking "definitely automated" can block your own monitoring. Start with managed_challenge.""") + "\n" + CHECK + "\n",

"security/ip-access-rules.yaml": header("security/ip-access-rules.yaml: allow, challenge or block by IP, range, ASN or country", """#
#   mode    whitelist (always allow) | block | managed_challenge | challenge | js_challenge
#   target  ip | ip6 | ip_range | asn | country
#   value   matching value (IPv4 /16 or /24, IPv6 /32/48/64 for ranges; country = two capital letters)
#   notes   Why the rule exists — please fill this in.
#
# For long lists, use an account IP list (account/lists/ip.yaml) instead.""", keys=True) + """
#
# EXAMPLE:
# office_allow:
#   mode: whitelist
#   target: ip_range
#   value: 203.0.113.0/24
#   notes: Head office
""" + CHECK + "\n",

"security/zone-hold.yaml": header("security/zone-hold.yaml: block the zone from being (de)activated by anyone but this pipeline", """#
#   enabled              true | false
#   include_subdomains   optional, default false
#
# Prevents zone hijack or accidental deletion: while a hold is in place,
# only this pipeline's Terraform can activate or deactivate the zone --
# not the dashboard, not the API, not even an account administrator
# without removing the hold first.""") + """
#
# EXAMPLE:
# enabled: true
# include_subdomains: true
""" + CHECK + "\n",

"security/total-tls.yaml": header("security/total-tls.yaml: automatic certificate issuance for every hostname", """#
#   enabled                true | false
#   certificate_authority  optional: lets_encrypt | google | ssl_com""") + """
#
# EXAMPLE:
# enabled: true
""" + CHECK + "\n",

"security/ct-alerting.yaml": header("security/ct-alerting.yaml: alert when a Certificate Transparency log sees a new cert for this zone", """#
#   enabled   true | false
#   emails    optional list; Cloudflare account emails are notified by default""") + """
#
# EXAMPLE:
# enabled: true
# emails: [security@example.com]
""" + CHECK + "\n",

"security/origin-cert.yaml": header("security/origin-cert.yaml: Cloudflare Origin CA certificate for your origin server", """#
#   csr                 a Certificate Signing Request YOU generate; the
#                       matching private key stays on your origin server,
#                       NEVER in this repo. A CSR is public, not secret.
#   hostnames           list of hostnames the cert covers
#   request_type        origin-rsa | origin-ecc
#   requested_validity  optional, days""") + """
#
# EXAMPLE:
# csr: |
#   -----BEGIN CERTIFICATE REQUEST-----
#   ...
#   -----END CERTIFICATE REQUEST-----
# hostnames: [example.com, "*.example.com"]
# request_type: origin-rsa
""" + CHECK + "\n",

"security/certificate-pack.yaml": header("security/certificate-pack.yaml: an ordered certificate pack (Advanced Certificate Manager)", """#
#   certificate_authority   lets_encrypt | google | ssl_com
#   type                    advanced | custom
#   validation_method       txt | http | email
#   validity_days           14 | 30 | 90 | 365 (varies by CA)
#   hosts                   optional, defaults to the zone's hostnames
#   cloudflare_branding     optional
#
# CAREFUL: ordering a certificate pack can be a billable action depending
# on the certificate authority and type -- check Cloudflare's pricing
# before enabling this.""") + """
#
# EXAMPLE:
# certificate_authority: lets_encrypt
# type: advanced
# validation_method: txt
# validity_days: 90
""" + CHECK + "\n",

"cache/settings.yaml": header("cache/settings.yaml: tiered cache and performance toggles", """#
#   smart_tiered_cache     "on" | "off"   all plans
#   argo_tiered_caching    "on" | "off"   only if you pay for Argo
#   cache_reserve          "on" | "off"   large objects kept in R2-backed storage; has its own cost
#   argo_smart_routing     "on" | "off"   only if you pay for Argo (routing, not caching)
#   regional_tiered_cache  "on" | "off"
#
# Keep the quotes around "on" and "off".""") + """
#
# smart_tiered_cache: "on"
""" + CHECK + "\n",

"cache/variants.yaml": header("cache/variants.yaml: image/media variants to cache per format", """#
# Per format, the list of MIME variants to serve when the browser
# requests that format (e.g. automatic AVIF/WebP delivery):
#   avif, bmp, gif, jp2, jpeg, jpg, jpg2, png, tif, tiff, webp: [MIME, ...]""") + """
#
# EXAMPLE:
# webp: [image/webp]
# avif: [image/avif]
""" + CHECK + "\n",

"cache/cache-rules.yaml": header("cache/cache-rules.yaml: cache rules (what Cloudflare caches and for how long)", """#
#   cache: true | false
#   edge_ttl:    { mode: override_origin, default: <seconds> }
#   browser_ttl: { mode: respect_origin }   or override_origin + default
#
# Needs the DNS record to be proxied (orange cloud).
# CAREFUL: never cache pages with personal data (accounts, carts, admin).""", rules=True) + """
#
# EXAMPLE:
# - ref: cache_static
#   description: Cache static assets at the edge for a day
#   expression: (http.request.uri.path.extension in {"css" "js" "png" "jpg" "svg" "woff2"})
#   action_parameters:
#     cache: true
#     edge_ttl:
#       mode: override_origin
#       default: 86400
""" + CHECK + "\n",

"rules/redirects.yaml": header("rules/redirects.yaml: single redirect rules", """#
#   from_value:
#     status_code: 301 (permanent) | 302 (temporary) | 307 | 308
#     preserve_query_string: true | false
#     target_url: { value: https://... }  or  { expression: concat(...) }
#
# For hundreds of fixed old-to-new addresses use Bulk Redirects instead
# (account/lists/redirect.yaml).""", rules=True) + """
#
# EXAMPLE:
# - ref: www_to_apex
#   description: Redirect www to the domain, keep path and query
#   expression: (http.host eq "www.example.com")
#   action_parameters:
#     from_value:
#       status_code: 301
#       preserve_query_string: true
#       target_url:
#         expression: concat("https://example.com", http.request.uri.path)
""" + CHECK + "\n",

"rules/url-rewrites.yaml": header("rules/url-rewrites.yaml: URL rewrite rules (visitor sees one URL, server gets another)", """#
#   uri.path:  { value: /new/path }   or  { expression: wildcard_replace(...) }
#   uri.query: { value: a=1 }         or  { expression: ... }
#
# wildcard_replace() works on all plans; regex_replace() needs Business+.""", rules=True) + """
#
# EXAMPLE:
# - ref: blog_to_news
#   description: /blog/* is served from /news/*
#   expression: (starts_with(http.request.uri.path, "/blog/"))
#   action_parameters:
#     uri:
#       path:
#         expression: wildcard_replace(http.request.uri.path, "/blog/*", "/news/${1}")
""" + CHECK + "\n",

"rules/request-headers.yaml": header("rules/request-headers.yaml: change request headers sent to your server", """#
#   headers.<Header-Name>: { operation: set | add | remove, value: text | expression: ... }
#
# Never put passwords or secrets here: this repository may be readable by many people.""", rules=True) + """
#
# EXAMPLE:
# - ref: tag_cf
#   description: Tell the server which country the visitor is in
#   expression: "true"
#   action_parameters:
#     headers:
#       X-Client-Country:
#         operation: set
#         expression: ip.src.country
""" + CHECK + "\n",

"rules/response-headers.yaml": header("rules/response-headers.yaml: change response headers sent to browsers", """#
#   headers.<Header-Name>: { operation: set | add | remove, value: text }
#
# Typical use: security headers.""", rules=True) + """
#
# EXAMPLE:
# - ref: security_headers
#   description: Baseline security headers
#   expression: "true"
#   action_parameters:
#     headers:
#       X-Frame-Options:
#         operation: set
#         value: SAMEORIGIN
""" + CHECK + "\n",

"rules/origin.yaml": header("rules/origin.yaml: origin rules (send some requests to a different server or port)", """#
#   origin: { port: 8443 }          all plans
#   origin: { host: other.example } Enterprise only (DNS record override)
#   host_header, sni                Enterprise only""", rules=True) + """
#
# EXAMPLE:
# - ref: api_port
#   description: The API server listens on 8443
#   expression: (starts_with(http.request.uri.path, "/api/"))
#   action_parameters:
#     origin:
#       port: 8443
""" + CHECK + "\n",

"rules/config.yaml": header("rules/config.yaml: configuration rules (different settings for some requests)", """#
# action_parameters takes zone settings that apply only when the rule matches, e.g.:
#   security_level: off | essentially_off | low | medium | high | under_attack
#   ssl: off | flexible | full | strict
#   rocket_loader, email_obfuscation, automatic_https_rewrites: true | false""", rules=True) + """
#
# EXAMPLE:
# - ref: admin_hardening
#   description: Stricter settings on admin pages
#   expression: (starts_with(http.request.uri.path, "/admin"))
#   action_parameters:
#     security_level: high
""" + CHECK + "\n",

"rules/compression.yaml": header("rules/compression.yaml: compression rules", """#
#   algorithms: [{ name: zstd | brotli | gzip | auto | default | none }, ...]  tried in order""", rules=True) + """
#
# EXAMPLE:
# - ref: prefer_zstd
#   description: Prefer Zstandard, then Brotli, then gzip
#   expression: "true"
#   action_parameters:
#     algorithms:
#       - name: zstd
#       - name: brotli
#       - name: gzip
""" + CHECK + "\n",

"settings/zone.yaml": header("settings/zone.yaml: zone settings (SSL, TLS, HTTPS, caching, speed)", """#
# One line per setting: setting_name: value
#
# QUOTE "on"/"off" and version numbers like "1.2", or Cloudflare rejects them
# (the check catches this). Numbers of seconds (browser_cache_ttl) have no quotes.
# Leaving a setting out means this repo does not manage it — it is not reset.
# HSTS is set in security/hsts.yaml, not here.""") + """
#
# RECOMMENDED BASELINE (remove the # to use):
# ssl: strict                       # off | flexible | full | strict
# min_tls_version: "1.2"
# always_use_https: "on"
# security_level: medium            # off | essentially_off | low | medium | high | under_attack
# browser_cache_ttl: 14400          # seconds; 0 = respect your server's headers
#
# More settings: docs/20-services.md
""" + CHECK + "\n",
}


def data_part(text):
    """Everything after the leading comment block (the file's own data)."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and (lines[i].startswith("#") or not lines[i].strip()):
        i += 1
    return "\n".join(lines[i:]).strip("\n")


def refresh(domain_dir):
    """Give an existing domain the current instructions, keeping its data."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from yamlio import header_of
    d = Path(domain_dir)
    for rel in FILES:
        tpl, f = T / rel, d / rel
        if not f.exists():
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(tpl.read_text(), encoding="utf-8", newline="\n")
            continue
        data = data_part(f.read_text(encoding="utf-8"))
        if not data:
            f.write_text(tpl.read_text(), encoding="utf-8", newline="\n")
        elif rel == "domain.yaml":
            f.write_text(header_of(tpl) + "\n" + data + "\n", encoding="utf-8", newline="\n")
        else:
            f.write_text(header_of(tpl) + "\n#\n# --- Your data starts below this line. ---\n" + data + "\n",
                         encoding="utf-8", newline="\n")
    print(f"refreshed instructions in {d}")


def main():
    for rel, text in FILES.items():
        p = T / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(FILES)} template files")
    for target in sys.argv[1:]:
        refresh(target)


if __name__ == "__main__":
    main()
