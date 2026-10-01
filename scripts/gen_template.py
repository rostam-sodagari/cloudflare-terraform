#!/usr/bin/env python3
"""
Write the documentation headers for every file in domains/_template.

The template files are the single source of the per-file instructions:
`make new` copies them and the exporter puts each header above exported
data. Edit the text here and run:

    python3 scripts/gen_template.py

Every example in a header is commented out, so a new domain changes nothing
until someone removes the # in front of the lines they want.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
T = ROOT / "domains" / "_template"

CHECK = """#
# Check your edit before opening a pull request (no token needed):
#   make validate D=<domain>        Windows: .\\cf.ps1 validate <domain>
# Or just open the pull request: CI runs the same check and marks the line."""

KEYS = """#
# HOW KEYS WORK
#   The name before the colon at the start of each block (for example
#   "www:") is that item's permanent ID. Change the fields under it freely,
#   but do not rename the key itself: renaming deletes the item and creates
#   a new one."""

DNS_COMMON = """#
# FIELDS USED BY EVERY RECORD
#   name     "@" for the domain itself, or a label such as www or mail.
#            A full name (www.example.com) also works. No trailing dot.
#   ttl      Seconds. Leave it out for "automatic" (recommended).
#            Allowed: 60 to 86400 (30 on Enterprise). Ignored when proxied.
#   comment  Optional note shown in the Cloudflare dashboard."""

RULES = """#
# FORMAT (same in every rules file)
#   - ref: unique_id        required; letters, digits, _ or -. Never reuse.
#     description: text     what the rule is for (shown in Cloudflare)
#     expression: (...)     WHEN the rule runs, in Cloudflare's rules language.
#                           Write "true" (with quotes) to match every request.
#                           Easiest: build it in the dashboard's expression
#                           editor, then copy the text here.
#     action_parameters:    WHAT the rule does (see the example below)
#     enabled: false        optional; keeps the rule but switches it off
#   Do not add an "action:" line; this file sets it for you.
#   Field names are Cloudflare's own API names, so examples from
#   developers.cloudflare.com can be copied in (as YAML).
#
# RULES RUN TOP TO BOTTOM. Moving a rule up or down changes behaviour.
# Limits: Free 10, Pro 25, Business 50, Enterprise 300 rules in this file.
# Regular expressions (matches, ~, regex_replace) need Business or above."""


def header(title, body, keys=False, dns=False, rules=False):
    parts = ["# " + "=" * 75, f"# {title}", "# " + "=" * 75, body.rstrip()]
    if keys:
        parts.append(KEYS)
    if dns:
        parts.append(DNS_COMMON)
    if rules:
        parts.append(RULES)
    return "\n".join(parts)


FILES = {
"domain.yaml": header("domain.yaml: which Cloudflare zone this folder controls (REQUIRED)", """#
#   name      The domain exactly as shown in Cloudflare, e.g. example.com.
#             Must match the folder name.
#   zone_id   The zone's Overview page > API section > Zone ID.
#             32 characters, 0-9 and a-f. Keep the quotes.
#   plan      free | pro | business | enterprise. Must match the real plan:
#             it decides which features and how many rules are allowed.
#   owner     Team responsible for this domain (for people; not used by Terraform).
#   example   Only for sample folders with fake IDs; CI never plans them.
#             Never set this on a real domain.
#
# Changing plan (e.g. after an upgrade) is a normal pull request.""") + "\n" + CHECK + """
name: DOMAIN_NAME
zone_id: "ZONE_ID"
plan: free
owner: change-me
""",

"dns/a.yaml": header("dns/a.yaml: A records (name -> IPv4 address)", """#
#   content  The IPv4 address, e.g. 203.0.113.10.
#   proxied  true  = orange cloud: traffic goes through Cloudflare (CDN, WAF,
#                    hides your server's IP). Use for websites.
#            false = grey cloud: DNS only. Use for mail servers, VPNs, SSH
#                    and anything that is not HTTP/HTTPS.
#            Leave it out for false.""", keys=True, dns=True) + """
#
# CAREFUL: changing content moves traffic for that name to a new server.
#
# EXAMPLES (remove the # to use):
# root:
#   name: "@"
#   content: 203.0.113.10
#   proxied: true
#
# vpn:
#   name: vpn
#   content: 198.51.100.5
#   proxied: false
#   ttl: 300
#   comment: VPN needs the real IP, so not proxied
""" + CHECK + "\n",

"dns/aaaa.yaml": header("dns/aaaa.yaml: AAAA records (name -> IPv6 address)", """#
#   content  The IPv6 address, e.g. 2001:db8::10.
#   proxied  As in a.yaml: true for websites, false for everything else.""", keys=True, dns=True) + """
#
# EXAMPLE:
# root_v6:
#   name: "@"
#   content: 2001:db8::10
#   proxied: true
""" + CHECK + "\n",

"dns/cname.yaml": header("dns/cname.yaml: CNAME records (name -> another hostname)", """#
#   content  The target hostname, e.g. myapp.herokuapp.com. No https://,
#            no path, no trailing dot.
#   proxied  true for websites, false for everything else.
#
#   A name that has a CNAME cannot have any other record (no A, MX or TXT
#   with the same name). The check stops you if you try.
#   Microsoft 365 DKIM uses CNAMEs, so it belongs here, not in dkim.yaml.""", keys=True, dns=True) + """
#
# EXAMPLES:
# www:
#   name: www
#   content: example.com
#   proxied: true
#
# m365_dkim_1:
#   name: selector1._domainkey
#   content: selector1-example-com._domainkey.tenant.onmicrosoft.com
""" + CHECK + "\n",

"dns/mx.yaml": header("dns/mx.yaml: MX records (where e-mail for the domain is delivered)", """#
#   content   The mail server's hostname, from your mail provider.
#   priority  Required. Lower number = tried first.""", keys=True, dns=True) + """
#
# CAREFUL: removing or mistyping an MX record stops e-mail from arriving.
# Copy values exactly from your mail provider's setup page.
#
# EXAMPLES:
# m365:
#   name: "@"
#   content: example-com.mail.protection.outlook.com
#   priority: 0
#
# google_1:
#   name: "@"
#   content: aspmx.l.google.com
#   priority: 1
""" + CHECK + "\n",

"dns/txt.yaml": header("dns/txt.yaml: TXT records (site verifications and other text)", """#
#   content  The exact text you were given, e.g. google-site-verification=abc.
#
#   SPF, DMARC and DKIM have their own files (spf.yaml, dmarc.yaml,
#   dkim.yaml). The check rejects SPF or DMARC records here.""", keys=True, dns=True) + """
#
# EXAMPLES:
# google_verification:
#   name: "@"
#   content: google-site-verification=abc123
#
# ms_verification:
#   name: "@"
#   content: MS=ms12345678
""" + CHECK + "\n",

"dns/ns.yaml": header("dns/ns.yaml: NS records (hand a SUBDOMAIN to other name servers)", """#
#   content  The other DNS provider's name server.
#
#   Only for subdomains. The domain's own NS records belong to Cloudflare
#   and cannot be set here.""", keys=True, dns=True) + """
#
# EXAMPLE (dev.example.com answered by another provider):
# dev_1:
#   name: dev
#   content: ns1.other-dns.example
# dev_2:
#   name: dev
#   content: ns2.other-dns.example
""" + CHECK + "\n",

"dns/spf.yaml": header("dns/spf.yaml: SPF (which servers may send e-mail as this domain)", """#
# You list the senders; the SPF text is built for you. One entry per name.
# The key is the name the policy is for: "@" for the domain itself, or a
# label such as mail for mail.example.com.
#
#   includes  Domains of services that send for you, e.g. spf.protection.outlook.com
#             (write only the domain; "include:" is added for you).
#   ip4/ip6   Addresses or ranges of your own mail servers.
#   a / mx    true to allow the domain's A or MX hosts.
#   extra     Anything else, copied as it is (e.g. "exists:%{i}.spf.example.com").
#   all       What receivers do with everything else:
#               "-all" reject (default, recommended)   "~all" mark as suspicious
#   raw       The complete SPF text instead of the fields above (used by the
#             exporter when it cannot rebuild a record exactly).
#
# Built as: v=spf1 a mx ip4:... ip6:... include:... extra... all
# The check fails if receivers would need more than 10 DNS lookups, because
# they then reject the record (RFC 7208).""") + """
#
# EXAMPLES:
# "@":
#   includes: [spf.protection.outlook.com, _spf.google.com]
#   ip4: [203.0.113.0/28]
#   all: "-all"
#
# A domain that never sends e-mail:
# "@":
#   all: "-all"
""" + CHECK + "\n",

"dns/dmarc.yaml": header("dns/dmarc.yaml: DMARC (what receivers do with mail that fails SPF/DKIM)", """#
# Published at _dmarc.<name>. The key is "@" for the domain itself.
#
#   policy            none (monitor only) | quarantine (spam folder) | reject
#   subdomain_policy  The same choices, for subdomains (sp=).
#   pct               0-100: share of failing mail the policy applies to.
#   rua               Addresses that receive daily summary reports.
#   ruf               Addresses for failure reports (rarely used).
#   adkim / aspf      r (relaxed, default) | s (strict) alignment.
#   raw               Complete DMARC text instead of the fields above.
#
# SAFE ROLLOUT: start with policy: none and an rua address, read the reports
# for a few weeks, then quarantine, then reject.""") + """
#
# EXAMPLE:
# "@":
#   policy: none
#   rua: [dmarc-reports@example.com]
""" + CHECK + "\n",

"dns/dkim.yaml": header("dns/dkim.yaml: DKIM keys published as TXT records", """#
# The key is the selector your mail provider gives you; the record is
# published at <selector>._domainkey.
#
#   content  The full key text from your mail provider (starts v=DKIM1).
#
# Microsoft 365 DKIM uses CNAME records instead: put those in cname.yaml.""") + """
#
# EXAMPLE:
# google:
#   content: v=DKIM1; k=rsa; p=MIIBIjANBgkqh...
""" + CHECK + "\n",

"dns/caa.yaml": header("dns/caa.yaml: CAA records (which certificate authorities may issue)", """#
#   tag    issue (certificates) | issuewild (wildcard certificates) | iodef (report address)
#   value  The CA's domain, e.g. letsencrypt.org, or mailto:... for iodef.
#   flags  0 (default) or 128.
#
# CAREFUL: once any CAA record exists, ONLY the listed CAs may issue.
# Cloudflare's own edge certificates come from Let's Encrypt and Google
# Trust Services, so keep letsencrypt.org and pki.goog in the list or
# certificate renewals fail. The check warns if they are missing.""", keys=True) + """
#
# EXAMPLES:
# letsencrypt:
#   tag: issue
#   value: letsencrypt.org
# google:
#   tag: issue
#   value: pki.goog
# report:
#   tag: iodef
#   value: mailto:security@example.com
""" + CHECK + "\n",

"dns/srv.yaml": header("dns/srv.yaml: SRV records (service discovery, e.g. Teams, SIP)", """#
#   name      _service._protocol, e.g. _sip._tls (or _sip._tls.voice for a subdomain)
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
# TURNING ON
#   1. status: active, open a PR, merge, approve.
#   2. Ask a maintainer for the DS record (Terraform output dnssec_ds) and add
#      it at the domain registrar.
#
# TURNING OFF (order matters, or the domain stops resolving):
#   1. Remove the DS record at the registrar.
#   2. Wait at least 24 to 48 hours.
#   3. status: disabled.
#   Never just delete this file once DNSSEC is managed: the plan refuses to,
#   to protect you from step 1 being forgotten.""") + """
#
# status: active
""" + CHECK + "\n",

"waf/custom-rules.yaml": header("waf/custom-rules.yaml: WAF custom rules (block, challenge or allow traffic)", """#
# FORMAT
#   - ref: unique_id        required; letters, digits, _ or -. Never reuse.
#     description: text     what and why (shown in Security > Events)
#     expression: (...)     WHEN the rule matches. Build it in the dashboard's
#                           expression editor, then copy the text here.
#     action: block         block | managed_challenge | js_challenge |
#                           challenge | skip | log (log is Enterprise only)
#     enabled: false        optional; keeps the rule but switches it off
#     response:             optional, paid plans, action block only:
#       status_code: 403      a custom block page
#       content_type: text/html
#       content: "<h1>Blocked</h1>"
#     skip:                 only with action: skip. What to skip:
#       ruleset: current      the remaining custom rules, and/or
#       phases: [http_ratelimit, http_request_firewall_managed]
#       products: [bic, hot, rateLimit, securityLevel, uaBlock, waf, zoneLockdown]
#
# RULES RUN TOP TO BOTTOM: put "skip" (allow) rules first.
# Limits: Free 5, Pro 20, Business 100, Enterprise 1000 rules.
# Regular expressions (matches, ~) need Business or above.
# To test a rule safely, use managed_challenge before block.""") + """
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
#
# - ref: block_ip_list
#   description: Block the account-level list "blocked_ips"
#   expression: (ip.src in $blocked_ips)
#   action: block
""" + CHECK + "\n",

"waf/rate-limits.yaml": header("waf/rate-limits.yaml: rate limiting (too many requests from one visitor)", """#
#   ref, description, expression     as in custom-rules.yaml
#   requests_per_period   Required. How many requests are allowed...
#   period                ...in this many seconds: 10, 60, 120, 300, 600, 3600
#   mitigation_timeout    Seconds the visitor stays blocked:
#                         0, 10, 60, 120, 300, 600, 3600, 86400
#   action                block (default) | managed_challenge | js_challenge | challenge
#   characteristics       Who counts as "one visitor". Default [ip.src, cf.colo.id];
#                         must always include cf.colo.id.
#   counting_expression   Business+: count only matching responses, e.g. failed logins.
#   response              Paid plans, action block only: custom status and body.
#
# WHAT EACH PLAN ALLOWS (Cloudflare docs)
#   Free      1 rule; period 10; timeout 10; by IP only
#   Pro       2 rules; period up to 60; timeout up to 3600; by IP only
#   Business  5 rules; period up to 600; timeout up to 86400; IP or IP with NAT
#   Enterprise 100 rules; everything above""") + """
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
# On Free, Cloudflare applies its Free Managed Ruleset itself: leave this
# file commented.
#
# SIMPLE FORM
#   cloudflare_managed:
#     enabled: true|false   Cloudflare Managed Ruleset (common attacks, CVEs)
#     action: <action>      optional: one action for every rule
#   owasp:
#     enabled: true|false   OWASP Core Ruleset (scores each request)
#     paranoia_level: 1-4   higher = stricter, more false positives (default 1)
#     score_threshold: 60 | 40 | 25   low | medium (default) | high sensitivity
#     action: <action>      what happens above the threshold. Leave it out
#                           for Cloudflare's default (block).
#   exceptions:             skip a ruleset for matching traffic (placed first)
#     - ref, description, expression, rulesets: [owasp | cloudflare_managed]
#
#   Actions: block | managed_challenge | js_challenge | challenge
#   "log" is Enterprise only. On Pro and Business, tune OWASP with
#   managed_challenge or a higher score_threshold (60) first.
#
# RAW FORM (written by the exporter)
#   raw_rules: [...]        the ruleset exactly as Cloudflare holds it. Edit
#                           with care; when raw_rules is present the simple
#                           form above is ignored.
#
# CAREFUL: emptying this file after it has been applied DELETES the managed
# WAF protection. The change summary warns you if that would happen.""") + """
#
# EXAMPLE:
# cloudflare_managed:
#   enabled: true
# owasp:
#   enabled: true
#   paranoia_level: 1
#   score_threshold: 60
#   action: managed_challenge
# exceptions:
#   - ref: skip_owasp_webhooks
#     description: Payment webhooks trip OWASP false positives
#     expression: (http.request.uri.path eq "/webhooks/payments")
#     rulesets: [owasp]
""" + CHECK + "\n",

"security/hsts.yaml": header("security/hsts.yaml: HSTS (browsers must always use HTTPS)", """#
#   enabled             true | false
#   max_age             Seconds browsers remember it. Start small (300),
#                       raise to 31536000 (one year) when confident.
#   include_subdomains  true applies it to every subdomain too.
#   preload             true asks browsers to build it in. Needs
#                       include_subdomains: true and max_age: 31536000.
#   nosniff             true also sends X-Content-Type-Options: nosniff.
#
# CAREFUL: browsers enforce HTTPS for max_age seconds even if you switch
# HSTS off. Only enable it when every hostname has working HTTPS.
# preload is very hard to undo (months).""") + """
#
# enabled: true
# max_age: 300
# include_subdomains: false
# preload: false
# nosniff: true
""" + CHECK + "\n",

"security/bot-management.yaml": header("security/bot-management.yaml: bot protection", """#
# Which settings exist depends on the plan; the check tells you if you use
# one your plan does not have.
#
# FREE: Bot Fight Mode
#   fight_mode: true
#
# PRO / BUSINESS: Super Bot Fight Mode
#   sbfm_definitely_automated: managed_challenge   allow | block | managed_challenge
#   sbfm_likely_automated: managed_challenge       Business and above
#   sbfm_verified_bots: allow                      allow | block (search engines etc.)
#   sbfm_static_resource_protection: false         also check images, CSS, JS
#   optimize_wordpress: true
#   enable_js: true                                invisible JavaScript detections
#
# ALL PLANS: AI crawlers
#   ai_bots_protection: block                      block | disabled | only_on_ad_pages
#   crawler_protection: disabled                   enabled | disabled
#
# ENTERPRISE BOT MANAGEMENT
#   auto_update_model: true
#   suppress_session_score: false
#
# CAREFUL: blocking "definitely automated" can block your own monitoring,
# APIs and integrations. Start with managed_challenge.""") + "\n" + CHECK + "\n",

"security/ip-access-rules.yaml": header("security/ip-access-rules.yaml: allow, challenge or block by IP, range, ASN or country", """#
#   mode    whitelist (always allow) | block | managed_challenge | challenge | js_challenge
#   target  ip | ip6 | ip_range | asn | country
#   value   ip        203.0.113.7
#           ip6       2001:db8::7
#           ip_range  IPv4 /16 or /24, IPv6 /32, /48 or /64
#           asn       AS64496
#           country   two capital letters, e.g. GB (T1 = Tor, XX = unknown).
#                     Blocking a whole country is Enterprise only; use
#                     managed_challenge or a WAF custom rule instead.
#   notes   Why the rule exists. Please always fill this in, so it can be
#           removed safely later.
#
# For long lists, use an account IP list (account/lists/ip.yaml) and a WAF
# custom rule such as: (ip.src in $office_ips)""", keys=True) + """
#
# EXAMPLES:
# office_allow:
#   mode: whitelist
#   target: ip_range
#   value: 203.0.113.0/24
#   notes: Head office
#
# bad_asn:
#   mode: block
#   target: asn
#   value: AS64496
#   notes: Abuse from this network, ticket SEC-123
""" + CHECK + "\n",

"cache/settings.yaml": header("cache/settings.yaml: tiered cache", """#
#   smart_tiered_cache   "on" | "off"   all plans; fewer requests reach your server
#   argo_tiered_caching  "on" | "off"   only if you pay for Argo
#
# Keep the quotes around "on" and "off".""") + """
#
# smart_tiered_cache: "on"
""" + CHECK + "\n",

"cache/cache-rules.yaml": header("cache/cache-rules.yaml: cache rules (what Cloudflare caches and for how long)", """#
# Common action_parameters:
#   cache: true | false                       cache it, or never cache it
#   edge_ttl:     { mode: override_origin, default: <seconds> }
#                 modes: respect_origin | override_origin | bypass_by_default
#   browser_ttl:  { mode: respect_origin }    or override_origin + default
#
# Cache rules need the DNS record to be proxied (orange cloud).
# CAREFUL: never cache pages that show personal data (accounts, carts, admin).""", rules=True) + """
#
# EXAMPLES:
# - ref: cache_static
#   description: Cache static assets at the edge for a day
#   expression: (http.request.uri.path.extension in {"css" "js" "png" "jpg" "svg" "woff2"})
#   action_parameters:
#     cache: true
#     edge_ttl:
#       mode: override_origin
#       default: 86400
#     browser_ttl:
#       mode: respect_origin
#
# - ref: bypass_dynamic
#   description: Never cache admin and API
#   expression: (starts_with(http.request.uri.path, "/admin") or starts_with(http.request.uri.path, "/api/"))
#   action_parameters:
#     cache: false
""" + CHECK + "\n",

"rules/redirects.yaml": header("rules/redirects.yaml: single redirect rules", """#
# action_parameters:
#   from_value:
#     status_code: 301 (permanent) | 302 (temporary) | 307 | 308
#     preserve_query_string: true | false
#     target_url:
#       value: https://example.com/new         a fixed address, or
#       expression: concat("https://example.com", http.request.uri.path)
#
# For hundreds of fixed old-to-new addresses use Bulk Redirects instead
# (account/lists/redirect.yaml).""", rules=True) + """
#
# EXAMPLES:
# - ref: www_to_apex
#   description: Redirect www to the domain, keep path and query
#   expression: (http.host eq "www.example.com")
#   action_parameters:
#     from_value:
#       status_code: 301
#       preserve_query_string: true
#       target_url:
#         expression: concat("https://example.com", http.request.uri.path)
#
# - ref: old_page
#   description: One page moved
#   expression: (http.request.uri.path eq "/old-page")
#   action_parameters:
#     from_value:
#       status_code: 301
#       target_url:
#         value: https://example.com/new-page
""" + CHECK + "\n",

"rules/url-rewrites.yaml": header("rules/url-rewrites.yaml: URL rewrite rules (visitor sees one URL, server gets another)", """#
# action_parameters:
#   uri:
#     path:  { value: /new/path }   or  { expression: wildcard_replace(...) }
#     query: { value: a=1 }         or  { expression: ... }
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
# action_parameters:
#   headers:
#     Header-Name:
#       operation: set | add | remove
#       value: text                  a fixed value, or
#       expression: ip.src.country   a value worked out per request
#
# Never put passwords or secrets here: this repository may be readable by
# many people.""", rules=True) + """
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
# Typical use: security headers.
# action_parameters:
#   headers:
#     Header-Name:
#       operation: set | add | remove
#       value: text""", rules=True) + """
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
#       Referrer-Policy:
#         operation: set
#         value: strict-origin-when-cross-origin
#       X-Powered-By:
#         operation: remove
""" + CHECK + "\n",

"rules/origin.yaml": header("rules/origin.yaml: origin rules (send some requests to a different server or port)", """#
# action_parameters:
#   origin: { port: 8443 }          all plans
#   origin: { host: other.example } Enterprise only (DNS record override)
#   host_header: other.example      Enterprise only
#   sni: { value: other.example }   Enterprise only""", rules=True) + """
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
# action_parameters takes zone settings that apply only when the rule
# matches, for example:
#   security_level: off | essentially_off | low | medium | high | under_attack
#   ssl: off | flexible | full | strict
#   rocket_loader: true | false
#   email_obfuscation: true | false
#   automatic_https_rewrites: true | false""", rules=True) + """
#
# EXAMPLE:
# - ref: admin_hardening
#   description: Stricter settings on admin pages
#   expression: (starts_with(http.request.uri.path, "/admin"))
#   action_parameters:
#     security_level: high
#     rocket_loader: false
""" + CHECK + "\n",

"rules/compression.yaml": header("rules/compression.yaml: compression rules", """#
# action_parameters:
#   algorithms:            tried in order; the first the browser supports wins
#     - name: zstd | brotli | gzip | auto | default | none""", rules=True) + """
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
# QUOTE "on" AND "off" and version numbers like "1.2". Without quotes YAML
# reads them as yes/no or numbers and Cloudflare rejects them; the check
# catches this. Numbers of seconds (browser_cache_ttl) have no quotes.
#
# Leaving a setting out means this repo does not manage it. Removing a line
# stops managing it; it does NOT reset the setting in Cloudflare.
# HSTS is set in security/hsts.yaml.""") + """
#
# RECOMMENDED BASELINE (remove the # to use):
# ssl: strict                       # off | flexible | full | strict
# min_tls_version: "1.2"            # "1.0" | "1.1" | "1.2" | "1.3"
# tls_1_3: "on"
# always_use_https: "on"
# automatic_https_rewrites: "on"
# opportunistic_encryption: "on"
#
# SECURITY:
# security_level: medium            # off | essentially_off | low | medium | high | under_attack
# browser_check: "on"
# email_obfuscation: "on"
#
# CACHING AND SPEED:
# browser_cache_ttl: 14400          # seconds; 0 = respect your server's headers
# cache_level: aggressive           # basic | simplified | aggressive
# brotli: "on"
# early_hints: "on"
# http3: "on"
# 0rtt: "on"
""" + CHECK + "\n",
}


def main():
    for rel, text in FILES.items():
        p = T / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(FILES)} template files")


if __name__ == "__main__":
    main()
