"""Enumerate and hash every input that can invalidate a saved plan."""
import hashlib


def plan_input_digests(r, repository_root):
    files = [repository_root / "cf.py", repository_root / "policy.yaml", repository_root / "requirements.txt"]
    files += list((repository_root / "modules").rglob("*.tf"))
    files += list((repository_root / "scripts").rglob("*.py"))
    files += list((repository_root / '.github/workflows').glob('*.yml'))
    files += list((repository_root / '.github/actions').rglob('*.yml'))
    files += [repository_root / '.github/cloudflare-operators.yml']
    files += [repository_root / "scripts" / "data" / "ruleset_rule_schema.json",
              repository_root / "backend.hcl", r.dir / ".terraform.lock.hcl"]
    files += [p for p in r.dir.rglob("*")
              if p.is_file() and p.suffix in {".tf", ".yaml", ".yml"}
              and p.name not in {"provider_override.tf", "backend_override.tf"}]
    return {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in set(files) if p.exists()}


def plan_fingerprint(r, backend, repository_root, inputs):
    """Hash every input that can change a root's Terraform plan."""
    digest = hashlib.sha256()
    digest.update(f"root={r.name}\nbackend={backend}\n".encode())
    for path in sorted(inputs):
        rel = path.relative_to(repository_root).as_posix()
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(inputs[path].encode())
        digest.update(b"\0")
    return digest.hexdigest()
