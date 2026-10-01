"""
Tiny in-memory stand-in for the Cloudflare v4 API, used only by
tests/e2e/run.sh. It stores whatever Terraform sends and returns it, honours
?dry_run=true like the real API (validates, stores nothing), and has
/__dump, /__patch and /__setting hooks so the test can make "dashboard"
edits behind Terraform's back.

    python3 tests/e2e/fake_cloudflare.py <port> [request-log]
"""
import json, re, sys, uuid, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STORE = {}      # collection path -> {id: obj}
SETTINGS = {}   # (zone, setting) -> value
LOG = open(sys.argv[2] if len(sys.argv) > 2 else "/dev/null", "a")

def ok(h, result, code=200):
    body = json.dumps({"success": True, "errors": [], "messages": [], "result": result,
                       "result_info": {"page": 1, "per_page": 100, "total_pages": 1, "count": 1, "total_count": 1}}).encode()
    h.send_response(code); h.send_header("Content-Type", "application/json"); h.send_header("Content-Length", str(len(body))); h.end_headers(); h.wfile.write(body)

def err(h, code, msg):
    body = json.dumps({"success": False, "errors": [{"code": code, "message": msg}], "messages": [], "result": None}).encode()
    h.send_response(code); h.send_header("Content-Type", "application/json"); h.send_header("Content-Length", str(len(body))); h.end_headers(); h.wfile.write(body)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}
    def route(self, method):
        path = self.path.split("?")[0].replace("/client/v4", "")
        LOG.write(f"{method} {self.path}\n"); LOG.flush()
        dry = "dry_run" in self.path or "dry-run" in self.path
        data = self.body() if method in ("POST", "PUT", "PATCH") else None
        if dry:  # validation only, like the real API: echo back, store nothing
            return ok(self, {**(data or {}), "id": "dry-run"})
        # test hooks: /__dump (read everything), /__patch and /__setting (drift)
        if path == "/__dump":
            return ok(self, {"store": STORE, "settings": {"/".join(k): v for k, v in SETTINGS.items()}})
        if path == "/__patch":
            coll, oid, fields = data["coll"], data["id"], data["fields"]
            if oid == "*":
                oid = next(iter(STORE[coll]))
            STORE[coll][oid].update(fields); return ok(self, STORE[coll][oid])
        if path == "/__setting":
            SETTINGS[(data["zone"], data["id"])] = data["value"]; return ok(self, {})
        m = re.match(r"^/zones/([^/]+)/(dnssec|bot_management|cache/tiered_cache_smart_topology_enable|argo/tiered_caching)$", path)
        if m:
            key = ("single", m.group(1), m.group(2))
            cur = SETTINGS.setdefault(key, {"id": m.group(2), "status": "disabled", "value": "off"} )
            if method in ("PATCH", "PUT", "POST"):
                cur.update(data)
            if method == "DELETE":
                SETTINGS.pop(key, None); return ok(self, {"id": m.group(2)})
            return ok(self, cur)
        m = re.match(r"^/zones/([^/]+)/settings/([^/]+)$", path)
        if m:
            key = (m.group(1), m.group(2))
            if method == "PATCH":
                SETTINGS[key] = data.get("value")
            v = SETTINGS.get(key, "off")
            return ok(self, {"id": key[1], "value": v, "editable": True, "modified_on": "2026-10-01T00:00:00Z"})
        m = re.match(r"^/zones/([^/]+)/rulesets/phases/([^/]+)/entrypoint$", path)
        if m:
            coll = f"/zones/{m.group(1)}/rulesets"
            items = [o for o in STORE.get(coll, {}).values() if o.get("phase") == m.group(2)]
            if method == "GET":
                return ok(self, items[0]) if items else err(self, 404, "not found")
            obj = items[0] if items else {"id": uuid.uuid4().hex, "phase": m.group(2), "kind": "zone"}
            obj.update(data); STORE.setdefault(coll, {})[obj["id"]] = obj
            for i, r in enumerate(obj.get("rules") or []):
                r.setdefault("id", uuid.uuid4().hex); r.setdefault("version", "1"); r.setdefault("ref", r["id"])
            return ok(self, obj)
        # generic collection / item
        parts = path.rstrip("/").split("/")
        is_item = len(parts) % 2 == 1 and parts[-1] not in ("dns_records", "rules", "rulesets", "lists", "items")
        coll = "/".join(parts[:-1]) if is_item else "/".join(parts)
        oid = parts[-1] if is_item else None
        store = STORE.setdefault(coll, {})
        if method == "GET":
            if oid:
                return ok(self, store[oid]) if oid in store else err(self, 404, "not found")
            return ok(self, list(store.values()))
        if method == "POST" and not oid and coll.endswith("/rulesets"):
            same = [o for o in store.values() if o.get("phase") == data.get("phase")]
            if same:  # dry runs and re-creates land on the same entry point
                same[0].update(data)
                for r in same[0].get("rules") or []:
                    r.setdefault("id", uuid.uuid4().hex); r.setdefault("version", "1"); r.setdefault("ref", r["id"])
                return ok(self, same[0])
        if method == "POST" and not oid:
            obj = dict(data); obj["id"] = uuid.uuid4().hex
            obj.setdefault("created_on", "2026-10-01T00:00:00Z"); obj.setdefault("modified_on", "2026-10-01T00:00:00Z")
            if coll.endswith("/rulesets"):
                for r in obj.get("rules") or []:
                    r.setdefault("id", uuid.uuid4().hex); r.setdefault("version", "1"); r.setdefault("ref", r["id"])
            if coll.endswith("/dns_records"):
                # Like Cloudflare: new TXT content saved without quotes gets them.
                if obj.get("type") == "TXT" and not str(obj.get("content", "")).startswith('"'):
                    obj["content"] = '"' + obj["content"] + '"'
                obj.setdefault("proxied", False); obj.setdefault("proxiable", True); obj.setdefault("ttl", 1)
                obj.setdefault("settings", {}); obj.setdefault("tags", []); obj.setdefault("meta", {})
            store[obj["id"]] = obj
            return ok(self, obj)
        if method in ("PUT", "PATCH") and oid:
            if oid not in store: return err(self, 404, "not found")
            if coll.endswith("/rulesets"):  # like the real API, a rule keeps its id while its ref is unchanged
                old = {r.get("ref"): r.get("id") for r in store[oid].get("rules") or []}
                for r in (data or {}).get("rules") or []:
                    if not r.get("id") and r.get("ref") in old:
                        r["id"] = old[r["ref"]]
            if method == "PUT":
                keep = {k: store[oid][k] for k in ("id", "created_on") if k in store[oid]}
                store[oid] = {**store[oid], **data, **keep}
            else:
                store[oid].update(data)
            if coll.endswith("/rulesets"):  # the real API gives every rule an id
                for r in store[oid].get("rules") or []:
                    r.setdefault("id", uuid.uuid4().hex); r.setdefault("version", "1"); r.setdefault("ref", r["id"])
            return ok(self, store[oid])
        if method == "DELETE" and oid:
            store.pop(oid, None); return ok(self, {"id": oid})
        return err(self, 404, f"unhandled {method} {path}")
    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_PATCH(self): self.route("PATCH")
    def do_DELETE(self): self.route("DELETE")

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
