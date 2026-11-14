"""Read-only reproduction and repair handoff against owner-approved inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import trustdiff_safe
import trustdiff_supply


def approved_inputs(args: argparse.Namespace) -> tuple[str, str]:
    import trustdiff

    trustdiff_safe.require_safe_git_config(trustdiff.ROOT)
    if os.environ.get("TRUSTDIFF_TRUST_GIT_CONFIG") == "1":
        raise ValueError("Git configuration override is incompatible with independent reproduction")
    if trustdiff.STATE.resolve().is_relative_to(trustdiff.ROOT.resolve()):
        raise ValueError("Set TRUSTDIFF_STATE_DIR to a protected directory outside the candidate")
    if trustdiff_supply.verifier_digest() != args.verifier_sha256:
        raise ValueError("Verifier digest differs from the approved value")
    baseline = trustdiff._resolve_commit(args.baseline)
    target = trustdiff._resolve_commit(args.target)
    if (baseline, target) != (args.baseline, args.target):
        raise ValueError("Use externally approved full Git commit IDs")
    path = args.contracts
    if not trustdiff_safe.clean_repo_path(path):
        raise ValueError("Invalid policy path")
    rc, data, _ = trustdiff_safe.run_git_bytes(trustdiff.ROOT, "show", f"{baseline}:{path}", max_output=1_000_000)
    if rc or hashlib.sha256(data).hexdigest() != args.policy_sha256:
        raise ValueError("Baseline policy digest differs from the approved value")
    return baseline, target


def reproduce(args: argparse.Namespace) -> int:
    import trustdiff
    import trustdiff_challenge

    baseline, original = approved_inputs(args)
    policy, source, _, drift, _ = trustdiff._tracked_baseline_policy(Path(args.contracts), baseline, original)
    if source == "untrusted" or drift:
        raise ValueError("Target policy differs from the approved baseline")
    case = next((item for item in policy if item["id"] == args.case and item.get("type") == "counterexample"), None)
    if case is None:
        raise ValueError("Case is absent from the approved counterexample policy")
    runtime = args.runtime
    cache = Path(args.lfs_cache) if args.lfs_cache else None
    before = trustdiff_challenge.evaluate(case, trustdiff.ROOT, baseline, original, "docker", args.image,
                                         trustdiff._contract_timeout(case), runtime, cache)
    result = {"protocol": "trustdiff.reproduction/v1", "case_id": args.case, "original": case_result(before),
              "policy_sha256": args.policy_sha256, "verifier_sha256": args.verifier_sha256,
              "runner": trustdiff.runner_metadata("docker", args.image, runtime)}
    if args.repair:
        repaired = trustdiff._resolve_commit(args.repair)
        if repaired != args.repair or repaired == original:
            raise ValueError("Repair requires a distinct full Git commit ID")
        rc, _, _ = trustdiff.git("merge-base", "--is-ancestor", original, repaired)
        if rc:
            raise ValueError("Repair must descend from the reproduced commit")
        if trustdiff.git_head() != repaired or not trustdiff._clean_worktree():
            raise ValueError("Check out the clean committed repair to run the full gate")
        _, _, _, policy_drift, _ = trustdiff._tracked_baseline_policy(Path(args.contracts), baseline, repaired)
        if policy_drift:
            raise ValueError("Repair altered the approved policy")
        if before[0] != "FAIL":
            print(json.dumps(result, indent=2))
            return 1
        after = trustdiff_challenge.evaluate(case, trustdiff.ROOT, baseline, repaired, "docker", args.image,
                                            trustdiff._contract_timeout(case), runtime, cache)
        result["repair"] = case_result(after)
        if after[0] == "PASS":
            gate_args = trustdiff.parser().parse_args([
                "check", "--baseline", baseline, "--contracts", args.contracts, "--runner", "docker",
                "--image", args.image, "--require-pinned-image", "--challenge-mode", "run",
                "--verifier-sha256", args.verifier_sha256,
                *(["--runtime", runtime] if runtime else []), *(["--lfs-cache", str(cache)] if cache else []),
            ])
            result["gate_exit"] = trustdiff.check_cmd(gate_args, quiet=True)
    print(json.dumps(result, indent=2))
    return (0 if before[0] == "FAIL" else 1) if not args.repair else (0 if result.get("gate_exit") == 0 else 1)


def case_result(outcome: tuple[str, str, dict]) -> dict:
    verdict, explanation, observations = outcome
    return {"verdict": verdict, "explanation": explanation, "observations": observations}


def plan(args: argparse.Namespace) -> int:
    import trustdiff
    import trustdiff_impact

    trustdiff_safe.require_safe_git_config(trustdiff.ROOT)
    baseline = trustdiff._resolve_commit(args.baseline or "HEAD")
    target = trustdiff.git_head()
    if args.working_tree:
        rc, raw, error = trustdiff_safe.run_git_bytes(trustdiff.ROOT, "diff", "--no-renames", "--no-ext-diff", "--no-textconv",
                                                       "--ignore-submodules=dirty", "--name-status", "-z", baseline, "--")
        if rc:
            raise ValueError(error or "Unable to inspect working changes")
        files = trustdiff_safe.parse_name_status_z(raw)
        rc, untracked, error = trustdiff_safe.run_git_bytes(trustdiff.ROOT, "ls-files", "--others", "--exclude-standard", "-z")
        if rc:
            raise ValueError(error or "Unable to inspect untracked paths")
        files.extend({"path": trustdiff_safe.git_path(path), "status": "?"} for path in untracked.split(b"\0") if path)
    else:
        files = trustdiff.changed_files(baseline, target)
    risks = trustdiff_impact.risk_topics(files)
    print(json.dumps({"protocol": "trustdiff.plan/v1", "kind": "diagnostic", "target": target, "baseline": baseline,
                      "risk_topics": risks[:200], "risk_count": len(risks)}, indent=2))
    return 0


def add_commands(sub: argparse._SubParsersAction) -> None:
    from trustdiff_runner import ALLOWED_RUNTIMES, image_is_pinned

    def pinned(value: str) -> str:
        if not image_is_pinned(value):
            raise argparse.ArgumentTypeError("image must be pinned by SHA-256 digest")
        return value

    diagnostic = sub.add_parser("plan", help="Show path-based risks without running candidate code")
    diagnostic.add_argument("--baseline")
    diagnostic.add_argument("--working-tree", action="store_true")
    diagnostic.set_defaults(func=plan)
    replay = sub.add_parser("reproduce", help="Run an approved counterexample, optionally followed by a repair and full gate")
    for flag in ("baseline", "target", "case", "policy-sha256", "verifier-sha256"):
        replay.add_argument("--" + flag, required=True)
    replay.add_argument("--contracts", default="trustdiff.contracts.json")
    replay.add_argument("--image", required=True, type=pinned)
    replay.add_argument("--runtime", choices=sorted(ALLOWED_RUNTIMES))
    replay.add_argument("--lfs-cache")
    replay.add_argument("--repair")
    replay.set_defaults(func=reproduce)
