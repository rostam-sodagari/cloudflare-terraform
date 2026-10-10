"""Validate an exact Freshservice change ID, approval, and timezone-aware window."""
import datetime
import json
from pathlib import Path
import re
import sys


def validate(reference, response, now=None):
    match = re.fullmatch(r'CHG-([0-9]+)', reference)
    change = response.get('change') or {}
    if not match or change.get('id') != int(match[1]):
        raise ValueError('Freshservice returned a different change ID')
    if change.get('approval_status') != 1 or change.get('deleted'):
        raise ValueError('The linked change is not approved')
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        start = datetime.datetime.fromisoformat(change['planned_start_date'])
        end = datetime.datetime.fromisoformat(change['planned_end_date'])
    except (KeyError, TypeError, ValueError):
        raise ValueError('The linked change has no valid deployment window') from None
    if start.tzinfo is None or end.tzinfo is None or not start <= now <= end:
        raise ValueError('Deployment is outside the approved change window')


if __name__ == '__main__':
    try:
        validate(sys.argv[1], json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')))
    except (ValueError, KeyError, OSError) as error:
        sys.exit(str(error))
