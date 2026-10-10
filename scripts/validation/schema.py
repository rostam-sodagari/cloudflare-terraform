"""Schema helpers for configuration validation."""
import json
from .paths import ROOT
from .checks import fmt_path, suggest

RULE_SCHEMA = json.loads((ROOT / "scripts" / "data" / "ruleset_rule_schema.json").read_text())["rule"]


def check_rule_schema(ctx, path, value, schema):
    """Recursively check a value against the provider rule schema."""
    if isinstance(schema, str):
        field_type, _, enum_values = schema.partition("|")
        if field_type == "string":
            if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                ctx.error(path, f"{fmt_path(path)} must be text, got {value!r}.", "put it in quotes")
            elif enum_values and str(value) not in enum_values.split(","):
                ctx.error(path, f"{fmt_path(path)} has invalid value '{value}'.", suggest(value, enum_values.split(",")))
        elif field_type == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                ctx.error(path, f"{fmt_path(path)} must be a number, got {value!r}.", "remove the quotes")
        elif field_type == "bool":
            if not isinstance(value, bool):
                ctx.error(path, f"{fmt_path(path)} must be true or false, got {value!r}.")
        elif field_type.startswith("["):
            collection, element = json.loads(field_type)
            expected = dict if collection == "map" else list
            if not isinstance(value, expected):
                ctx.error(path, f"{fmt_path(path)} must be a {expected.__name__}.")
                return
            entries = value.items() if isinstance(value, dict) else enumerate(value)
            for key, item in entries:
                check_rule_schema(ctx, path + (key,), item,
                                  json.dumps(element) if isinstance(element, list) else element)
        return
    if "__list__" in schema:
        if not isinstance(value, list):
            ctx.error(path, f"{fmt_path(path)} must be a list ('- ' items).")
            return
        for index, field_value in enumerate(value):
            check_rule_schema(ctx, path + (index,), field_value, schema["__list__"])
        return
    if "__map__" in schema:
        if not isinstance(value, dict):
            ctx.error(path, f"{fmt_path(path)} must be a set of 'name: settings' entries.")
            return
        for field_name, field_value in value.items():
            check_rule_schema(ctx, path + (field_name,), field_value, schema["__map__"])
        return
    if not isinstance(value, dict):
        ctx.error(path, f"{fmt_path(path)} must be a set of 'field: value' lines.")
        return
    for field_name, field_value in value.items():
        if field_name not in schema:
            ctx.error(path + (field_name,), f"unknown field '{field_name}' in {fmt_path(path)}.", suggest(field_name, schema))
        elif field_value is not None:
            check_rule_schema(ctx, path + (field_name,), field_value, schema[field_name])
