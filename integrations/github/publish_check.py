"""Publish a verified TrustDiff verdict using a GitHub App installation token."""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

from trustdiff_proof import _read_json, bundle_assessment, valid_repository


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def publish(args, token, endpoint=None):
    if not valid_repository(args.repository):
        raise ValueError("Expected a GitHub owner/repository")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise ValueError("Expected a full GitHub commit SHA")
    for digest in (args.policy, args.verifier):
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Expected approved SHA-256 digests")
    bundle = _read_json(Path(args.bundle))
    errors, _ = bundle_assessment(bundle, Path(args.signers), args.principal, args.commit, args.policy, args.verifier, True)
    if errors:
        raise ValueError("Evidence authentication failed: " + "; ".join(errors[:8]))
    if bundle["report"]["baseline_commit"] != args.baseline:
        raise ValueError("Evidence baseline does not match the approved PR base")
    if bundle["report"].get("repository") != args.repository.lower():
        raise ValueError("Evidence is not bound to the requested GitHub repository")
    verdict = bundle["report"]["overall_verdict"]
    report_hash = bundle["statement"]["predicate"]["report_sha256"]
    payload = {"name": "TrustDiff Independent Verification", "head_sha": args.commit, "status": "completed",
               "conclusion": "success" if verdict == "PASS" else "failure",
               "external_id": hashlib.sha256(f"{args.repository}:{args.commit}:{report_hash}".encode()).hexdigest(),
               "output": {"title": f"Authenticated {verdict}", "summary": f"TrustDiff report SHA-256: `{report_hash}`"}}
    req = urllib.request.Request(f"https://api.github.com/repos/{args.repository}/check-runs",
                                 data=json.dumps(payload).encode(), method="POST", headers={
                                     "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                     "Content-Type": "application/json",
                                 })
    opener = endpoint or urllib.request.build_opener(NoRedirect()).open
    with opener(req, timeout=20) as response:
        body = response.read(65_537)
        if len(body) > 65_536 or response.status != 201:
            raise ValueError("Unexpected response from GitHub")
        return json.loads(body)["id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("bundle", "repository", "principal", "signers", "commit", "baseline", "policy", "verifier"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    token = os.environ.get("TRUSTDIFF_GITHUB_INSTALLATION_TOKEN")
    if not token:
        parser.error("TRUSTDIFF_GITHUB_INSTALLATION_TOKEN is required")
    try:
        print(json.dumps({"check_run_id": publish(args, token)}))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"GitHub check was not confirmed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
