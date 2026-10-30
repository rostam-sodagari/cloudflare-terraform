"""Bind immutable PR plan artifacts to a non-author review and merged deployment."""
import argparse
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
from workflow.inventory import collect, require_complete, require_preserved, save, redact, differences, record
from workflow.semantics import digest, effects, state_only, reported_effects
from workflow.reconciliation import terraform
from workflow.files import resolve_root
from exporting.client import Client
from repository_paths import ROOT
from workflow.integrity import plan_input_digests
from types import SimpleNamespace


def gh(*arguments):
    result = subprocess.run(["gh", *arguments], capture_output=True, text=True,
                            encoding="utf-8", timeout=120)
    if result.returncode:
        raise RuntimeError("GitHub review evidence could not be read")
    return json.loads(result.stdout)


def merged_pr(repository, revision):
    pages = gh("api", '--paginate', '--slurp', f"repos/{repository}/commits/{revision}/pulls?per_page=100")
    pulls = [pull for page in pages for pull in page]
    matches = [pull for pull in pulls if pull.get("merged_at") and
               pull.get("merge_commit_sha") == revision and pull["base"]["ref"] == "main"]
    if len(matches) != 1:
        raise RuntimeError("This revision is not one approved merged PR; direct pushes and fresh manual changes cannot deploy")
    return matches[0]


def approvers(pull, reviews, report_time):
    latest = {}
    for review in sorted(reviews, key=lambda item: item.get("submitted_at") or ""):
        if review.get("state") != "COMMENTED":
            latest[review["user"]["login"]] = review
    result = []
    for user, review in sorted(latest.items(), key=lambda item: item[1].get("submitted_at") or ""):
        if user != pull["user"]["login"] and review.get("state") == "APPROVED" and \
                review.get("commit_id") == pull["head"]["sha"] and review["submitted_at"] >= report_time:
            result.append(user)
    if any(review.get("state") == "CHANGES_REQUESTED" for review in latest.values()):
        raise RuntimeError("PR has an unresolved request for changes")
    if not result:
        raise RuntimeError("A second user must approve this PR revision after the plan report was generated")
    return result


def schema(root):
    return json.loads(terraform(root, "providers", "schema", "-json"))


def bind_artifacts(root):
    import hashlib
    marker = json.loads((root / ".plan-input.sha256").read_text(encoding="ascii"))
    for name in (".review.json", ".inventory.json"):
        marker["artifacts"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    save(root / ".plan-input.sha256", marker)


def build(root):
    import datetime
    snapshot = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
    require_complete(snapshot)
    before = json.loads((root / ".inventory-before.json").read_text(encoding="utf-8"))
    if before["digest"] != snapshot["digest"]:
        raise RuntimeError("Cloudflare changed during PR planning; rerun before review")
    plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
    require_preserved(snapshot, plan)
    save(root / ".inventory.json", snapshot)
    provider_schema = schema(root)
    save(root / ".provider-schema.json", provider_schema)
    planned_effects = effects(plan, provider_schema)
    payload = {"version": 1, "root": root.name, "head": os.environ.get("PR_HEAD_SHA"),
               "base": os.environ.get("PR_BASE_SHA"), "pr": os.environ.get("PR_NUMBER"),
               "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "inventory": snapshot["digest"], "effects_digest": digest(planned_effects),
               "inputs": {path.relative_to(ROOT).as_posix(): value for path, value in
                          plan_input_digests(SimpleNamespace(dir=root), ROOT).items()},
               "effects": redact(reported_effects(plan, provider_schema))}
    save(root / ".review.json", payload)
    bind_artifacts(root)
    # Full semantic effects have no truncation and no broad noise filter.
    (root / "plan-details.md").write_text("# Complete reviewed effects\n\n```json\n" +
        json.dumps(redact(payload["effects"]), indent=2, ensure_ascii=False) + "\n```\n\n## Dashboard coverage\n\n" +
        '\n'.join(f"- {name}: {item['status']}; {'exportable' if item['exportable'] else 'observation only'}"
                  for name, item in snapshot['observations'].items()) +
        '\n\n## Current observed configuration\n\n```json\n' +
        json.dumps(redact(snapshot['observations']), indent=2, ensure_ascii=False) + '\n```\n\n## Coverage gaps\n\n' +
        '\n'.join('- ' + message for message in snapshot.get('gaps', []) + snapshot.get('limitations', [])) + '\n', encoding="utf-8")


def verify(root):
    repository, revision = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    pull = merged_pr(repository, revision)
    runs = gh("api", "--paginate", "--slurp", f"repos/{repository}/actions/workflows/cloudflare.yml/runs?event=pull_request&head_sha={pull['head']['sha']}&per_page=100")
    candidates = [run for page in runs for run in page["workflow_runs"] if run["conclusion"] == "success" and
                  run["head_sha"] == pull["head"]["sha"] and
                  any(item["number"] == pull["number"] for item in run.get("pull_requests", []))]
    if not candidates:
        raise RuntimeError("No successful PR workflow exists for the reviewed head")
    run = max(candidates, key=lambda item: item["id"])
    artifacts = gh("api", '--paginate', '--slurp', f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100")
    expected = f"review-{pull['number']}-{pull['head']['sha']}-{root.name}"
    matches = [artifact for page in artifacts for artifact in page["artifacts"] if artifact["name"] == expected and not artifact["expired"]]
    if len(matches) != 1:
        raise RuntimeError("Reviewed plan artifact is missing or expired; obtain a fresh PR review")
    with tempfile.TemporaryDirectory(prefix="review-evidence-") as directory:
        result = subprocess.run(["gh", "run", "download", str(run["id"]), "--repo", repository,
                                 "--name", expected, "--dir", directory], timeout=120)
        if result.returncode:
            raise RuntimeError("Cannot download immutable review evidence")
        reviewed = json.loads((Path(directory) / ".review.json").read_text(encoding="utf-8"))
    if reviewed["head"] != pull["head"]["sha"] or str(reviewed["pr"]) != str(pull["number"]) or reviewed["root"] != root.name:
        raise RuntimeError("Review artifact belongs to another revision, PR, or root")
    reviews = gh("api", "--paginate", "--slurp", f"repos/{repository}/pulls/{pull['number']}/reviews?per_page=100")
    reviewers = approvers(pull, [review for page in reviews for review in page], reviewed["created"])
    eligible = [user for user in reviewers if gh('api', f'repos/{repository}/collaborators/{user}/permission').get('permission')
                in ('write', 'maintain', 'admin')]
    if not eligible:
        raise RuntimeError('Approval must come from a second user with repository write permission')
    reviewed["approvers"] = eligible
    snapshot = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
    require_complete(snapshot)
    inputs = {path.relative_to(ROOT).as_posix(): value for path, value in
              plan_input_digests(SimpleNamespace(dir=root), ROOT).items()}
    if inputs != reviewed["inputs"]:
        raise RuntimeError("Deployment inputs differ from the reviewed PR; obtain fresh review")
    # Account apply legitimately changes account state, not the zone inventory.
    if snapshot["digest"] != reviewed["inventory"]:
        raise RuntimeError("Cloudflare changed since PR review; update the PR plan and obtain fresh approval")
    plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
    require_preserved(snapshot, plan)
    if digest(effects(plan, schema(root))) != reviewed["effects_digest"]:
        raise RuntimeError("Deployment differs from the approved PR effects; no changes applied")
    save(root / ".review.json", reviewed)
    save(root / ".inventory.json", snapshot)
    bind_artifacts(root)
    from workflow.journal import Journal
    Journal(root.name).start('pending', revision=revision, reviewed_at=reviewed['created'])


def reviewers(root):
    print("logins=" + " ".join(json.loads((root / ".review.json").read_text(encoding="utf-8"))["approvers"]))


def preflight(root):
    snapshot = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
    require_complete(snapshot)
    baseline = json.loads((root / ".inventory.json").read_text(encoding="utf-8"))
    if snapshot["digest"] != baseline["digest"]:
        raise RuntimeError("Cloudflare changed while deployment was pending; obtain fresh PR review")
    terraform(root, "plan", "-input=false", "-lock-timeout=60s", "-out=.preflight.bin")
    fresh = json.loads(terraform(root, "show", "-json", ".preflight.bin"))
    require_preserved(snapshot, fresh)
    reviewed = json.loads((root / "plan.json").read_text(encoding="utf-8"))
    evidence = json.loads((root / ".review.json").read_text(encoding="utf-8"))
    provider_schema = schema(root)
    if digest(effects(reviewed, provider_schema)) != evidence["effects_digest"]:
        raise RuntimeError("Saved plan does not match the approved PR evidence")
    if effects(fresh, provider_schema) != effects(reviewed, provider_schema):
        raise RuntimeError("The saved plan no longer describes current deployment effects")
    after = collect(Client(os.environ['CLOUDFLARE_API_TOKEN']), root)
    require_complete(after)
    if after['digest'] != snapshot['digest']:
        raise RuntimeError('Cloudflare changed during deployment preflight; obtain fresh review')
    (root / ".preflight.bin").unlink(missing_ok=True)


def snapshot(root):
    value = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
    require_complete(value)
    save(root / ".inventory-before.json", value)


def outcome(root):
    current = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
    baseline = json.loads((root / ".inventory.json").read_text(encoding="utf-8")) if (root / ".inventory.json").exists() else None
    changed = differences(current, None if baseline is None else record(baseline))
    report = {"root": root.name, "changed_services": changed, "problems": current["problems"],
              "configuration": redact({name: current["observations"][name] for name in changed}),
              "notice": "A failed apply can have partial effects. Review live configuration and state before recovery."}
    try:
        state = json.loads(terraform(root, 'state', 'pull'))
        report['state'] = {key: state.get(key) for key in ('lineage', 'serial')}
        terraform(root, 'plan', '-input=false', '-lock-timeout=60s', '-out=.outcome.bin')
        remaining = json.loads(terraform(root, 'show', '-json', '.outcome.bin'))
        report['remaining_effects'] = redact(reported_effects(remaining, schema(root)))
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        report['recovery_observation'] = str(error)
    finally:
        (root / '.outcome.bin').unlink(missing_ok=True)
    save(root / "deployment-outcome.json", report)
    print(json.dumps(report, indent=2))


def complete(root):
    from workflow.journal import Journal
    journal = Journal(root.name)
    plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
    if not state_only(plan):
        journal.finish("not-converged")
        raise RuntimeError("Deployment did not converge; automatic resync is blocked for recovery")
    value = collect(Client(os.environ["CLOUDFLARE_API_TOKEN"]), root)
    require_complete(value)
    terraform(root, 'plan', '-input=false', '-lock-timeout=60s', '-out=.verify.bin')
    verify = json.loads(terraform(root, 'show', '-json', '.verify.bin'))
    latest = collect(Client(os.environ['CLOUDFLARE_API_TOKEN']), root)
    require_complete(latest)
    if not state_only(verify) or latest['digest'] != value['digest']:
        journal.finish('verification-failed')
        raise RuntimeError('Cloudflare changed during convergence verification; recovery review is required')
    (root / '.verify.bin').unlink(missing_ok=True)
    journal.finish("complete", observed=record(value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["build", "verify", "reviewers", "preflight", "merged-pr", "snapshot", "outcome", "complete"])
    parser.add_argument("root", nargs="?")
    args = parser.parse_args()
    if args.command == "merged-pr":
        pull = merged_pr(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"])
        print(pull["number"])
    else:
        globals()[args.command](resolve_root(ROOT, args.root))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
