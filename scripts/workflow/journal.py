"""Small signed S3 journal beside Terraform state; contains no configuration values."""
import datetime
import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
import subprocess
import copy
from repository_paths import ROOT


class Conflict(RuntimeError):
    """An R2 conditional write was rejected."""


class Journal:
    def __init__(self, name):
        config = (ROOT / "backend.hcl").read_text(encoding="utf-8")
        self.bucket = re.search(r'(?m)^bucket\s*=\s*"([^"]+)"', config)[1]
        self.endpoint = re.search(r's3\s*=\s*"([^"]+)"', config)[1].rstrip("/")
        self.key = f"operations/{name}.json"
        self.owner = os.environ.get("GITHUB_RUN_ID", str(uuid.uuid4()))

    def request(self, method, value=None, condition=None):
        body = b"" if value is None else json.dumps(value, sort_keys=True).encode("utf-8")
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        parsed = urllib.parse.urlsplit(self.endpoint)
        if parsed.scheme != "https" or parsed.path not in ("", "/"):
            raise RuntimeError("Operational journal requires a direct HTTPS S3 endpoint")
        path = "/" + urllib.parse.quote(self.bucket + "/" + self.key, safe="/")
        payload_hash = hashlib.sha256(body).hexdigest()
        headers = {"host": parsed.netloc, "x-amz-content-sha256": payload_hash, "x-amz-date": stamp}
        if condition:
            headers["if-match" if condition != "*" else "if-none-match"] = condition
        names = ";".join(sorted(headers))
        canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
        canonical_request = f"{method}\n{path}\n\n{canonical_headers}\n{names}\n{payload_hash}"
        scope = f"{day}/auto/s3/aws4_request"
        signed = f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        key = ("AWS4" + os.environ["AWS_SECRET_ACCESS_KEY"]).encode()
        for part in (day, "auto", "s3", "aws4_request"):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, signed.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={os.environ['AWS_ACCESS_KEY_ID']}/{scope}, SignedHeaders={names}, Signature={signature}"
        request = urllib.request.Request(self.endpoint + path, data=body if method == "PUT" else None,
                                         method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                content = response.read()
                return (json.loads(content) if content else {}), response.headers.get("ETag")
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404 and method == "GET":
                return {}, None
            if error.code in (409, 412):
                raise Conflict("Another operation changed the state journal; this run must stop") from None
            raise RuntimeError(f"Operational journal {method} failed (HTTP {error.code}); do not assume deployment was rolled back") from None

    def read(self):
        value, tag = self.request("GET")
        if value and not tag:
            raise RuntimeError('Existing operational journal has no ETag; conditional recovery is unavailable')
        return value, tag

    def verify_conditions(self):
        """Use an isolated temporary key to check conditional writes before state work."""
        probe = copy.copy(self)
        probe.key = f'operations/.probe-{uuid.uuid4()}.json'
        created = False
        try:
            _, first = probe.request('PUT', {'probe': 'first'}, '*')
            created = True
            if not first:
                raise RuntimeError('R2 conditional-write probe returned no ETag')
            _, second = probe.request('PUT', {'probe': 'second'}, first)
            if not second or first == second:
                raise RuntimeError('R2 conditional-write probe did not advance its ETag')
            for condition in (first, '*'):
                try:
                    probe.request('PUT', {'probe': 'unexpected'}, condition)
                except Conflict:
                    continue
                raise RuntimeError('R2 ignored a conditional write; operational journal is unsafe')
            value, _ = probe.read()
            if value != {'probe': 'second'}:
                raise RuntimeError('R2 conditional-write probe changed unexpectedly')
        finally:
            if created:
                probe.request('DELETE')

    def start(self, kind, **details):
        if kind not in ('apply', 'pending', 'resync'):
            raise ValueError('Unknown operation kind')
        self.verify_conditions()
        current, tag = self.read()
        phase = current.get("phase", "complete")
        own_pending = kind == 'apply' and phase == 'approved-pending' and current.get('owner') == self.owner
        if phase in ("applying", "reconciling", 'approved-pending') and not own_pending:
            owner = current.get("owner", "")
            repository = current.get("repository")
            if not repository or not str(owner).isdigit():
                raise RuntimeError("An operation is active or interrupted; inspect its journal before recovery")
            result = subprocess.run(["gh", "api", f"repos/{repository}/actions/runs/{owner}"],
                                    capture_output=True, text=True, encoding="utf-8", timeout=120)
            if result.returncode or json.loads(result.stdout).get("status") != "completed":
                raise RuntimeError("The previous operation has not been confirmed stopped")
            phase = "resync-failed" if phase == "reconciling" else "apply-failed"
        if kind == "resync" and phase in ("apply-failed", "not-converged", "verification-failed"):
            raise RuntimeError("An incomplete approved deployment requires recovery; dashboard resync cannot overwrite its remaining changes")
        if kind in ('apply', 'pending') and not own_pending and phase != "complete" and datetime.datetime.fromisoformat(details.get("reviewed_at", "1970-01-01T00:00:00Z")) <= datetime.datetime.fromisoformat(current["updated"]):
            raise RuntimeError("Recovery requires a newly reviewed PR plan after the failed operation")
        self.request("PUT", {**current, **details, "owner": self.owner,
                            "repository": os.environ.get("GITHUB_REPOSITORY"),
                            "phase": {'apply': 'applying', 'pending': 'approved-pending', 'resync': 'reconciling'}[kind],
                            "updated": datetime.datetime.now(datetime.timezone.utc).isoformat()}, tag or "*")

    def finish(self, phase, **details):
        current, tag = self.read()
        if current.get("owner") != self.owner:
            raise RuntimeError("Operational journal belongs to a different run")
        self.request("PUT", {**current, **details, "phase": phase,
                            "updated": datetime.datetime.now(datetime.timezone.utc).isoformat()}, tag)
