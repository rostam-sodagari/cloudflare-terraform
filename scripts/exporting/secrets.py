"""Recognize destination credentials before an exporter writes configuration."""
from urllib.parse import parse_qsl, urlsplit


def sensitive_destination(value):
    parsed = urlsplit(value)
    public_options = {'region', 'account-id', 'bucket', 'path', 'dataset'}
    return bool(parsed.username or parsed.password or
                any(key.lower() not in public_options for key, _ in parse_qsl(parsed.query, keep_blank_values=True)))


def sensitive_webhook(value):
    parsed = urlsplit(value)
    return sensitive_destination(value) or parsed.hostname in ('hooks.slack.com', 'discord.com', 'discordapp.com')
