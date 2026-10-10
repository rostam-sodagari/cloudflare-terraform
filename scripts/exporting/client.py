"""Read-only HTTP client with Cloudflare retries and pagination."""
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from .config import API, PERMISSIONS


class NotFound(Exception):
    pass


class Client:
    def __init__(self, token):
        self.token = token

    def get(self, path, params=None):
        url = f"{API}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
        for attempt in range(5):
            request = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}",
                                                       "User-Agent": "cloudflare-terraform-export"})
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                body = error.read().decode(errors="replace")
                if error.code == 404:
                    raise NotFound(path)
                if error.code in (429, 500, 502, 503, 504) and attempt < 4:
                    time.sleep(int(error.headers.get("Retry-After") or 2 ** attempt))
                    continue
                if error.code in (401, 403):
                    required_permission = next((permission for endpoint, permission in PERMISSIONS if endpoint in path), "the matching Read permission")
                    raise PermissionError(f"token cannot read {path}: add '{required_permission}' to the API token") from None
                raise RuntimeError(f"{path}: HTTP {error.code} {body[:300]}") from None
            except urllib.error.URLError as error:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"cannot reach the Cloudflare API: {error.reason}") from None
        raise RuntimeError(f"{path}: gave up after retries")

    def result(self, path, params=None):
        return self.get(path, params)["result"]

    def pages(self, path, per_page=100):
        page, results = 1, []
        while True:
            body = self.get(path, {"page": page, "per_page": per_page})
            results += body["result"] or []
            if page >= (body.get("result_info") or {}).get("total_pages", 1):
                return results
            page += 1
