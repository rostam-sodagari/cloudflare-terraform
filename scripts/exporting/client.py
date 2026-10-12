"""Read-only HTTP client with Cloudflare retries and pagination."""
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime
import datetime
from .config import API, PERMISSIONS


class NotFound(Exception):
    pass


class UnavailableForPlan(NotFound):
    """An explicit Cloudflare entitlement denial, distinct from missing permissions."""
    pass


class SettingUnavailable(NotFound):
    """Cloudflare denies access to this specific add-on setting, not the token."""
    pass


class InventoryChanged(RuntimeError):
    """A list/count disagreement requires a new complete read, never a write."""


def retry_delay(header, attempt):
    try:
        seconds = float(header) if header else 2 ** attempt
    except ValueError:
        try:
            seconds = (parsedate_to_datetime(header) - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            seconds = 2 ** attempt
    return max(0, min(seconds, 30))


class Client:
    def __init__(self, token):
        self.token = token

    def get(self, path, params=None):
        url = f"{API}{path}" + (("&" if "?" in path else "?") + urllib.parse.urlencode(params) if params else "")
        for attempt in range(5):
            request = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}",
                                                       "User-Agent": "cloudflare-terraform-export"})
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    body = json.load(response)
                    if not isinstance(body, dict) or body.get("success") is False or "result" not in body:
                        raise RuntimeError(f"{path}: unsuccessful or incomplete API response")
                    return body
            except urllib.error.HTTPError as error:
                if (error.code == 403 and "/cache/" in path) or (error.code == 401 and path.endswith("/argo/smart_routing")):
                    try:
                        failure = json.load(error)
                        codes = {item.get("code") for item in failure.get("errors", [])}
                    except (ValueError, AttributeError, TypeError):
                        codes = set()
                    if codes == {1135}:
                        error.close()
                        raise UnavailableForPlan(path) from None
                    if error.code == 401 and codes == {1015} and any(
                            "Cause(s): smart_routing" in item.get("message", "") for item in failure.get("errors", [])):
                        error.close()
                        raise SettingUnavailable(path) from None
                error.close()
                if error.code == 404:
                    raise NotFound(path)
                if error.code in (429, 500, 502, 503, 504) and attempt < 4:
                    time.sleep(retry_delay(error.headers.get("Retry-After"), attempt))
                    continue
                if error.code in (401, 403):
                    required_permission = next((permission for endpoint, permission in PERMISSIONS if endpoint in path), "the matching Read permission")
                    raise PermissionError(f"token cannot read {path}: add '{required_permission}' to the API token") from None
                raise RuntimeError(f"{path}: HTTP {error.code}; API request failed") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"cannot reach the Cloudflare API: {getattr(error, 'reason', str(error))}") from None
        raise RuntimeError(f"{path}: gave up after retries")

    def result(self, path, params=None):
        return self.get(path, params)["result"]

    def pages(self, path, per_page=100):
        # Rulesets use cursor pagination, not numbered pages, and cap batches at 50.
        if path.split("?", 1)[0].rstrip("/").endswith("/rulesets"):
            return self.cursor_pages(path, per_page=min(per_page, 50))
        for attempt in range(4):
            try:
                return self.numbered_pages(path, per_page)
            except InventoryChanged:
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)

    def numbered_pages(self, path, per_page):
        page, results, seen_pages = 1, [], set()
        seen_ids = set()
        expected_count = None
        while True:
            body = self.get(path, {"page": page, "per_page": per_page})
            batch = body["result"]
            if not isinstance(batch, list):
                raise RuntimeError(f"{path}: expected a paginated array")
            signature = json.dumps(batch, sort_keys=True)
            if batch and signature in seen_pages:
                raise RuntimeError(f"{path}: repeated page; refusing an incomplete inventory")
            seen_pages.add(signature)
            for item in batch:
                identity = (item.get('id') or item.get('sitekey')) if isinstance(item, dict) else None
                if identity:
                    if identity in seen_ids:
                        raise RuntimeError(f'{path}: overlapping object IDs across pages; inventory is incomplete')
                    seen_ids.add(identity)
            results += batch
            info = body.get("result_info") or {}
            total_pages = info.get("total_pages")
            count = info.get('total_count')
            if count is not None:
                if not isinstance(count, int) or count < 0:
                    raise RuntimeError(f'{path}: invalid inventory count during pagination')
                if expected_count is not None and count != expected_count:
                    raise InventoryChanged(f'{path}: inventory count changed during pagination')
                expected_count = count
            if total_pages is not None and (not isinstance(total_pages, int) or total_pages < 0):
                raise RuntimeError(f"{path}: invalid pagination metadata")
            if total_pages is not None and page >= max(total_pages, 1):
                if info.get("total_count") is not None and len(results) != info["total_count"]:
                    raise InventoryChanged(f"{path}: inventory count does not match pagination metadata")
                return results
            if total_pages is None and expected_count is not None and len(results) == expected_count:
                return results
            if total_pages is None and len(batch) < per_page:
                if expected_count is not None and len(results) != expected_count:
                    if not batch or len(results) > expected_count:
                        raise InventoryChanged(f'{path}: inventory count does not match pagination metadata')
                    page += 1
                    if page > 10000:
                        raise RuntimeError(f'{path}: pagination did not terminate')
                    continue
                return results
            page += 1
            if page > 10000:
                raise RuntimeError(f"{path}: pagination did not terminate")

    def cursor_pages(self, path, per_page=50):
        results, seen_ids, seen_cursors = [], set(), set()
        cursor = None
        for _ in range(10000):
            params = {"per_page": per_page}
            if cursor:
                params["cursor"] = cursor
            body = self.get(path, params)
            batch = body["result"]
            if not isinstance(batch, list):
                raise RuntimeError(f"{path}: expected a cursor-paginated array")
            for item in batch:
                identity = item.get("id") if isinstance(item, dict) else None
                if not identity or identity in seen_ids:
                    raise RuntimeError(f"{path}: missing or overlapping object IDs during cursor pagination")
                seen_ids.add(identity)
            results.extend(batch)
            cursor = ((body.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cursor:
                return results
            if not isinstance(cursor, str) or cursor in seen_cursors or not batch:
                raise RuntimeError(f"{path}: invalid or repeated cursor; inventory is incomplete")
            seen_cursors.add(cursor)
        raise RuntimeError(f"{path}: cursor pagination did not terminate")
