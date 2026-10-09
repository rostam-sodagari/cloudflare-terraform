"""Zone settings (settings/zone.yaml): any Cloudflare setting ID, with
quoting/enum checks for the ones this repo knows about."""
from config import DEPRECATED_TLS_VERSIONS, WEAK_SSL_MODES

from config import KNOWN_SETTINGS, ON_OFF_SETTINGS, SETTING_ENUMS
from .common import Ctx, check_enum, check_type, load, suggest


def validate_settings(report, d, plan):
    f = d / "settings" / "zone.yaml"
    data, lines = load(report, f)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, f, lines, plan)
    if not check_type(ctx, (), data, "dict"):
        return
    for k, v in data.items():
        p = (str(k),)
        k = str(k)
        if k == "security_header":
            ctx.error(p, "HSTS is set in security/hsts.yaml, not here.")
            continue
        if k not in KNOWN_SETTINGS:
            ctx.warn(p, f"'{k}' is not a setting this repo knows.", suggest(k, KNOWN_SETTINGS) + " (ignore if it is a new Cloudflare setting)")
        if isinstance(v, bool):
            ctx.error(p, f"{k}: {str(v).lower()} was read as yes/no, but Cloudflare expects the text \"{'on' if v else 'off'}\".",
                      f'write {k}: "{"on" if v else "off"}" with the quotes')
            continue
        if k in ON_OFF_SETTINGS:
            check_enum(ctx, p, v, ["on", "off"])
        if k in SETTING_ENUMS:
            if isinstance(v, (int, float)):
                ctx.error(p, f"{k} was read as a number.", f'put it in quotes: "{v}"')
            else:
                check_enum(ctx, p, v, SETTING_ENUMS[k])
        if k == "browser_cache_ttl" and not isinstance(v, int):
            ctx.error(p, "browser_cache_ttl must be a number of seconds.", "remove the quotes")
        if k == "ssl" and v in WEAK_SSL_MODES:
            ctx.flag("ssl_not_weak", p, f"ssl: {v} sends traffic to your origin unencrypted.", "use full or strict")
        if k == "min_tls_version" and v in DEPRECATED_TLS_VERSIONS:
            ctx.flag("tls_version_current", p, "TLS 1.0 and 1.1 are deprecated.", 'use "1.2"')
