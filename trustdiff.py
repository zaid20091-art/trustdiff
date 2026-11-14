#!/usr/bin/env python3
"""TrustDiff: evidence-first verification for repository changes.

The first slice is intentionally conservative: execution-dependent checks fail closed
unless the user explicitly opts into host execution with --allow-host-execution.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import trustdiff_impact
import trustdiff_challenge
import trustdiff_runner
import trustdiff_proof
import trustdiff_repair
import trustdiff_safe

VERSION = "0.4.0"

VERDICTS = {"PASS", "FAIL", "UNKNOWN", "ERROR", "WAIVED"}
ROOT = Path.cwd()
STATE = Path(os.environ.get("TRUSTDIFF_STATE_DIR", str(ROOT / ".trustdiff")))


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(cmd: list[str], cwd: Path = ROOT, timeout: int = 30) -> tuple[int, str, str]:
    """Run a command with a hard time limit and bounded memory (last 1 MiB per stream kept; child killed above 64 MiB)."""
    if os.name == "nt" and cmd[0] in {"python3", "python"}:
        cmd = [sys.executable, *cmd[1:]]
    result = trustdiff_safe.bounded_run(cmd, cwd=cwd, timeout=timeout, max_output=1024 * 1024, tail=True)
    out, err = result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")
    if result.timed_out:
        return 124, out, f"timeout after {timeout}s"
    if result.truncated:
        return trustdiff_safe.RC_OVERFLOW, out, "output limit exceeded; process killed"
    return result.rc, out, err


def git(*args: str) -> tuple[int, str, str]:
    return trustdiff_safe.run_git(ROOT, *args)


def repo_digest() -> str:
    rc, out, err = git("ls-files", "-s")
    if rc:
        raise RuntimeError(err.strip() or "not a git repository")
    return sha256_bytes(out.encode())


def worktree_digest() -> str:
    """Hash tracked and relevant untracked contents, not only the index."""
    rc, tracked, err = trustdiff_safe.run_git_bytes(ROOT, "ls-files", "-z")
    if rc:
        raise RuntimeError(err.strip() or "not a git repository")
    rc, untracked, err = trustdiff_safe.run_git_bytes(ROOT, "ls-files", "--others", "--exclude-standard", "-z")
    if rc:
        raise RuntimeError(err.strip() or "unable to enumerate untracked files")
    h = hashlib.sha256()
    paths = tracked.split(b"\0") + untracked.split(b"\0")
    excluded = {b".git", b".trustdiff"}
    for raw_path in sorted(set(p for p in paths if p and not any(p == x or p.startswith(x + b"/") for x in excluded))):
        if not raw_path:
            continue
        h.update(raw_path + b"\0")
        name = trustdiff_safe.git_path(raw_path)
        path = ROOT / name
        if trustdiff_safe.clean_repo_path(name) and path.parent.resolve().is_relative_to(ROOT.resolve()):
            digest, note = trustdiff_safe.regular_file_sha256(path)
        else:
            digest, note = None, "unsupported path"
        h.update(f"{note}:{digest or ''}".encode())
    return h.hexdigest()


def input_snapshot() -> dict[str, Any]:
    """Capture a compact, reproducible description of verification inputs."""
    rc, tracked, _ = trustdiff_safe.run_git_bytes(ROOT, "ls-files", "-z")
    rc2, untracked, _ = trustdiff_safe.run_git_bytes(ROOT, "ls-files", "--others", "--exclude-standard", "-z")
    if rc or rc2:
        raise ValueError("cannot enumerate snapshot inputs")
    paths = sorted(set(tracked.split(b"\0") + untracked.split(b"\0")))
    files = []
    for raw in paths:
        if not raw or raw.startswith(b".git/") or raw.startswith(b".trustdiff/"):
            continue
        name = trustdiff_safe.git_path(raw)
        if not trustdiff_safe.clean_repo_path(name):
            files.append({"path": name, "error": "unsupported path"})
            continue
        path = ROOT / name
        if not path.parent.resolve().is_relative_to(ROOT.resolve()):
            files.append({"path": name, "error": "path escapes worktree"})
            continue
        if path.is_symlink():
            link = os.readlink(path)
            files.append({"path": os.fsdecode(raw), "type": "symlink", "sha256": sha256_bytes(os.fsencode(link)), "target": link})
        elif trustdiff_safe.is_regular_file(path):
            digest, note = trustdiff_safe.regular_file_sha256(path)
            if digest is None:
                files.append({"path": os.fsdecode(raw), "error": note})
            else:
                files.append({"path": os.fsdecode(raw), "sha256": digest, "size": os.lstat(path).st_size})
        elif path.exists() or path.is_symlink():
            files.append({"path": os.fsdecode(raw), "error": "not-a-regular-file"})
    dependency_files = [p for p in files if Path(p["path"]).name in {"pyproject.toml", "poetry.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "requirements.txt"}]
    return {"files": files, "dependency_files": dependency_files, "environment": env_info(), "fingerprint": sha256_bytes(json.dumps(files, sort_keys=True).encode())}


def git_head() -> str:
    rc, out, err = git("rev-parse", "HEAD")
    if rc:
        raise RuntimeError(err.strip() or "unable to resolve HEAD")
    return out.strip()


def changed_files(baseline: str, target: str) -> list[dict[str, str]]:
    """Exact changed paths (NUL-delimited: no quoting, tab or newline ambiguity)."""
    rc, out, err = trustdiff_safe.run_git_bytes(ROOT, "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-status", "-z", baseline, target)
    if rc:
        raise RuntimeError(err.strip() or "unable to compute diff")
    return trustdiff_safe.parse_name_status_z(out)


def risk_plan(files: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Produce review priorities, never a verdict."""
    plan = []
    for item in files:
        path = item["path"].lower()
        if any(x in path for x in ("auth", "permission", "rbac", "security")):
            risk, checks = "critical", ["authorization-positive-negative", "security-contracts"]
        elif any(x in path for x in ("migration", "schema", "database")):
            risk, checks = "high", ["migration-up-down", "restore-check"]
        elif any(x in path for x in ("payment", "billing", "money", "finance")):
            risk, checks = "critical", ["accounting-invariants", "differential-regression"]
        elif path.endswith((".md", ".txt")):
            risk, checks = "low", ["links-and-format"]
        else:
            risk, checks = "medium", ["targeted-regression"]
        plan.append({"path": item["path"], "risk": risk, "recommended_checks": checks})
    return plan


def semantic_hypotheses(baseline: str, target: str) -> list[dict[str, str]]:
    """Find high-signal change patterns; these are hypotheses, not proof."""
    rc, diff, _ = git("diff", "--unified=0", "--no-ext-diff", "--no-textconv", baseline, target)
    if rc:
        return []
    patterns = [
        (r"role\s*(!=|not in)|admin|guest", "Authorization condition may have widened or narrowed; require positive and negative access tests."),
        (r"except\s*:|except\s+\w+|raise", "Exception behavior changed; require failure-path and invariant tests."),
        (r"default|ALLOW|DENY|timeout|verify", "Security-sensitive default or gate may have changed; require explicit boundary tests."),
        (r"float|Decimal|round|NaN|Infinity", "Numerical behavior may have changed; require edge-case and reproducibility tests."),
    ]
    seen = set(); findings = []
    for regex, message in patterns:
        if re.search(regex, diff, re.IGNORECASE) and message not in seen:
            findings.append({"kind": "semantic_hypothesis", "message": message, "evidence": "git diff pattern"})
            seen.add(message)
    return findings


def append_ledger(record: dict[str, Any]) -> str:
    """Append a tamper-evident hash-chain entry; never overwrite prior evidence."""
    path = STATE / "ledger.jsonl"
    previous = "GENESIS"
    if path.exists():
        lines = ledger_lines(path)
        if lines:
            previous = json.loads(lines[-1])["entry_hash"]
    payload = {"previous_hash": previous, **record}
    entry_hash = sha256_bytes(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode())
    payload["entry_hash"] = entry_hash
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    lines = ledger_lines(path)
    save_json(STATE / "ledger.anchor.json", {"entry_count": len(lines), "head_hash": entry_hash})
    return entry_hash


def ledger_lines(path: Path) -> list[str]:
    raw = trustdiff_safe.read_regular_text(path, 16 * 1024 * 1024)
    if raw is None:
        raise ValueError("ledger is oversized, unreadable or not a regular file")
    return raw.splitlines()


def verify_ledger(state: Path | None = None) -> dict[str, Any]:
    """Verify every hash-chain link and every archived report fingerprint.

    `state` defaults to the module-level STATE so existing callers are unaffected;
    the evidence validator passes an explicit directory.
    """
    state = STATE if state is None else state
    path = state / "ledger.jsonl"
    errors: list[str] = []
    entries: list[dict[str, Any]] = []
    previous = "GENESIS"
    if path.exists():
        for line_no, line in enumerate(ledger_lines(path), 1):
            try:
                entry = json.loads(line)
                if not isinstance(entry, dict):
                    raise ValueError("expected object")
            except (ValueError, RecursionError):
                errors.append(f"line {line_no}: invalid JSON")
                continue
            claimed = entry.get("entry_hash")
            payload = {k: v for k, v in entry.items() if k != "entry_hash"}
            calculated = sha256_bytes(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode())
            if claimed != calculated:
                errors.append(f"line {line_no}: entry hash mismatch")
            if entry.get("previous_hash") != previous:
                errors.append(f"line {line_no}: previous_hash does not link to the prior entry")
            report_hash = entry.get("report_hash")
            archive = state / "evidence" / f"{report_hash}.json" if isinstance(report_hash, str) and re.fullmatch("[0-9a-f]{64}", report_hash) else None
            if not archive or not trustdiff_safe.is_regular_file(archive):
                errors.append(f"line {line_no}: archived report for {report_hash} is missing")
            else:
                actual, _ = trustdiff_safe.regular_file_sha256(archive, limit=trustdiff_proof.MAX_JSON)
                if actual != report_hash:
                    errors.append(f"line {line_no}: archived report fingerprint mismatch")
            previous = claimed or "<invalid>"
            entries.append(entry)
    anchor_path = state / "ledger.anchor.json"
    if not anchor_path.exists():
        errors.append("ledger anchor is missing")
    else:
        anchor = load_json(anchor_path)
        if anchor.get("entry_count") != len(entries):
            errors.append("ledger entry count differs from anchor")
        if entries and anchor.get("head_hash") != entries[-1].get("entry_hash"):
            errors.append("ledger head differs from anchor")
    return {"valid": not errors, "entries": len(entries), "latest_report_hash": entries[-1].get("report_hash") if entries else None,
            "errors": errors, "limitation": "A local hash chain detects modification, deletion, and reordering of retained records. External trust anchors are required to authenticate the chain."}


def verify_ledger_cmd(_: argparse.Namespace) -> int:
    result = verify_ledger()
    result["trust"] = "tamper-evident only: a local hash chain cannot show who wrote it. Use signed proof bundles (verify-proof) for origin."
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["valid"] else 1


def verify_claims(path: Path, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.stat().st_size > 1_000_000:
        raise ValueError("Claims file exceeds 1 MB limit")
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("claims", []), list) or any(not isinstance(c, dict) or not isinstance(c.get("requirements", []), list) for c in data.get("claims", [])):
        raise ValueError("Claims file must contain a claims array of objects with requirement lists")
    by_id = {r["contract_id"]: r["verdict"] for r in results}
    verified = []
    for claim in data.get("claims", []):
        requirements = claim.get("requirements", [])
        states = [by_id.get(req, "UNKNOWN") for req in requirements]
        verdict = "PASS" if states and all(s == "PASS" for s in states) else "FAIL" if "FAIL" in states else "UNKNOWN"
        explanation = "Agent claim is supported only by all technically passing obligations." if verdict == "PASS" else "Administrative waiver is not technical proof; claim remains unproven." if "WAIVED" in states else "Claim is not independently proven."
        verified.append({"claim_id": claim.get("claim_id", "UNNAMED"), "agent": claim.get("agent", "unknown"), "claim": claim.get("claim", ""), "requirements": requirements, "requirement_verdicts": states, "verdict": verdict, "explanation": explanation})
    return verified


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


@dataclass
class Evidence:
    evidence_id: str
    contract_id: str
    method: str
    input_fingerprint: str
    tool_version: str
    environment: dict[str, str]
    exit_code: int | None
    output: str
    started_at: str
    finished_at: str
    limitations: list[str]
    runner: dict[str, str] | None = None


@dataclass
class Result:
    contract_id: str
    verdict: str
    evidence_ids: list[str]
    baseline_commit: str
    target_commit: str
    checker_version: str
    explanation: str
    limitations: list[str]


def env_info() -> dict[str, str]:
    return {"python": sys.version.split()[0], "platform": sys.platform, "cwd": str(ROOT)}


_NO_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_CONTRACTS = 500


def _is_str(value: Any, limit: int) -> bool:
    return isinstance(value, str) and len(value) <= limit and "\x00" not in value


def validate_contracts(contracts: Any) -> None:
    """Strict, bounded schema for policy that may originate from an untrusted repository. Raises ValueError."""
    if not isinstance(contracts, list) or len(contracts) > MAX_CONTRACTS:
        raise ValueError(f"contracts must be a list of at most {MAX_CONTRACTS} entries")
    seen: set[str] = set()
    for c in contracts:
        if not isinstance(c, dict):
            raise ValueError("Every contract must be an object")
        cid = c.get("id")
        if not _is_str(cid, 200) or not cid or _NO_CONTROL.search(cid):
            raise ValueError("Every contract must have a valid id (1-200 printable characters)")
        if cid in seen:
            raise ValueError("Duplicate contract ids are prohibited")
        seen.add(cid)
        covers = c.get("covers", [])
        if not isinstance(covers, list) or len(covers) > 50 or any(not _is_str(x, 100) for x in covers):
            raise ValueError(f"{cid}: covers must be a list of up to 50 short strings")
        for field in ("description", "type", "match", "pattern", "runner", "target"):
            if field in c and not _is_str(c[field], 2000):
                raise ValueError(f"{cid}: {field} must be a string of at most 2000 characters")
        for field in ("required", "require_approval"):
            if field in c and not isinstance(c[field], bool):
                raise ValueError(f"{cid}: {field} must be a boolean")
        if "timeout_seconds" in c:
            t = c["timeout_seconds"]
            if isinstance(t, bool) or not isinstance(t, int) or not 1 <= t <= 600:
                raise ValueError(f"{cid}: timeout_seconds must be an integer between 1 and 600")
        if "command" in c:
            cmd = c["command"]
            if not isinstance(cmd, list) or not cmd or len(cmd) > 64 or any(not _is_str(x, 4096) for x in cmd):
                raise ValueError(f"{cid}: command must be a non-empty array of at most 64 strings")
        if c.get("type") == "counterexample":
            trustdiff_challenge.validate_case(c)
        if "trusted_script" in c:
            script = c["trusted_script"]
            if c.get("type") != "test" or not isinstance(script, str) or not script.endswith(".py") or not trustdiff_safe.clean_repo_path(script):
                raise ValueError(f"{cid}: trusted_script requires a baseline-relative Python test script")


def _contract_timeout(contract: dict[str, Any]) -> int:
    t = contract.get("timeout_seconds", 30)
    return t if isinstance(t, int) and not isinstance(t, bool) and 1 <= t <= 600 else 30


def evaluate_contract(contract: dict[str, Any], baseline: str, target: str, runner_mode: str, image: str, require_pinned_image: bool = False, runtime: str | None = None, lfs_cache: Path | None = None) -> tuple[Result, Evidence]:
    cid = str(contract.get("id", "UNNAMED"))
    method = str(contract.get("type", "unknown"))
    started = now()
    limitations: list[str] = []
    exit_code: int | None = None
    output = ""
    verdict = "UNKNOWN"
    explanation = "No deterministic checker is registered for this contract type."
    execution = method in {"test", "counterexample"}
    runner = runner_metadata(runner_mode if execution else "not-executed", image, runtime)

    if execution and runner_mode == "docker" and require_pinned_image and not trustdiff_runner.image_is_pinned(image):
        verdict = "ERROR"
        explanation = "Execution refused: --require-pinned-image needs an image reference ending in @sha256:<64 hex>."
        limitations.append("Runner image is not pinned by digest")
    elif method == "counterexample":
        verdict, explanation, details = trustdiff_challenge.evaluate(
            contract, ROOT, baseline, target, runner_mode, image, _contract_timeout(contract), runtime, lfs_cache
        )
        output = json.dumps(details, sort_keys=True)
        limitations.append("Covers the approved calls and values. Candidate code shares its process with the observation worker.")
    elif method == "policy":
        pattern = str(contract.get("match", ""))
        files = changed_files(baseline, target)
        matches = [f["path"] for f in files if pattern.endswith("/**") and (f["path"] == pattern[:-3] or f["path"].startswith(pattern[:-2]))]
        if not matches and pattern and not pattern.endswith("/**"):
            matches = [f["path"] for f in files if f["path"] == pattern]
        if matches and contract.get("require_approval", False):
            verdict = "UNKNOWN"
            explanation = f"Protected paths changed without an independently recorded approval: {', '.join(matches)}"
            limitations.append("Approval verification is not implemented in this prototype.")
        else:
            verdict = "PASS"
            explanation = "No protected path matched the policy."
    elif method == "test":
        command = contract.get("command")
        if not command:
            runner = str(contract.get("runner", ""))
            target_path = str(contract.get("target", ""))
            command = [runner, target_path] if runner and target_path else None
        if contract.get("trusted_script"):
            script_rc, script, _ = trustdiff_safe.run_git_bytes(ROOT, "show", f"{baseline}:{contract['trusted_script']}", max_output=250_000)
            if script_rc:
                exit_code, stdout, stderr = 127, "", "Trusted script unavailable in baseline"
            else:
                exit_code, stdout, stderr = trustdiff_challenge.execute_script(
                    ROOT, target, script.decode("utf-8"), runner_mode, image, _contract_timeout(contract), runtime, lfs_cache
                )
            output = (stdout + "\n" + stderr).strip()[-12000:]
            verdict = "PASS" if exit_code == 0 else "ERROR" if exit_code in (124, 125, 126, 127) or exit_code < 0 else "FAIL"
            explanation = f"Baseline-owned script exited {exit_code}."
            limitations.append("Run the verifier on a separate protected worker for independent evidence.")
        elif not isinstance(command, list) or not all(isinstance(x, str) for x in command):
            verdict = "ERROR"
            explanation = "Test contract requires a command array of strings."
        elif runner_mode == "none":
            verdict = "ERROR"
            explanation = "Execution refused: select --runner docker or explicitly opt into unsafe host execution."
            limitations.append("Missing isolated execution authorization")
        else:
            timeout = _contract_timeout(contract)
            if runner_mode == "docker":
                options = {"lfs_cache": lfs_cache} if lfs_cache is not None else {}
                exit_code, stdout, stderr = trustdiff_runner.run_docker(command, ROOT, image, timeout, commit=target, runtime=runtime, **options)
                limitations.append("Docker isolation is not a VM boundary; the host and Docker daemon must be trusted")
                if "@sha256:" not in image:
                    limitations.append("Container image is not pinned by an immutable digest; this result cannot be signed")
            else:
                exit_code, stdout, stderr = run(command, timeout=timeout)
                limitations.append("Unsafe host execution is not independent evidence")
            output = (stdout + ("\n" + stderr if stderr else "")).strip()[-12000:]
            verdict = "PASS" if exit_code == 0 else "ERROR" if exit_code in (124, 125, 126, 127) or exit_code < 0 else "FAIL"
            explanation = "Test command completed successfully." if verdict == "PASS" else f"Test command exited with code {exit_code}."
    elif method == "deny_pattern":
        pattern = contract.get("pattern", "")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
            verdict, explanation = "ERROR", "deny_pattern requires a regular expression up to 256 characters"
        else:
            rc, diff, error = git("diff", "--unified=0", "--no-ext-diff", "--no-textconv", baseline, target)
            if rc:
                verdict, explanation = "ERROR", "Could not read the diff (" + (error.strip()[:120] or f"rc={rc}") + "); refusing to pass without inspecting it"
            else:
                added_lines = []
                in_hunk = False
                for line in diff.split("\n"):
                    if line.startswith("diff --git "):
                        in_hunk = False
                    elif line.startswith("@@ "):
                        in_hunk = True
                    elif in_hunk and line.startswith("+"):
                        added_lines.append(line[1:])
                matched, regex_error = trustdiff_safe.regex_hits(pattern, added_lines)
                if regex_error:
                    verdict, explanation = "ERROR", regex_error
                else:
                    output = "\n".join(matched)[:4000]
                    verdict = "FAIL" if matched else "PASS"
                    explanation = "Forbidden pattern occurs in added source lines." if matched else "No forbidden added line matched the heuristic pattern."
                    limitations.append("A static pattern cannot prove security or semantic correctness")
    else:
        limitations.append(f"Unsupported contract type: {method}")

    finished = now()
    eid = f"E-{sha256_bytes((cid + started + output).encode())[:16]}"
    evidence = Evidence(eid, cid, method, sha256_bytes(json.dumps(contract, sort_keys=True).encode()), f"trustdiff/{VERSION}", env_info(), exit_code, output, started, finished, limitations, runner)
    result = Result(cid, verdict, [eid], baseline, target, f"trustdiff/{VERSION}", explanation, limitations)
    return result, evidence


def runner_metadata(mode: str, image: str, runtime: str | None) -> dict[str, str]:
    docker = mode == "docker"
    return {"mode": mode, "image": image if docker else "", "runtime": (runtime or "default") if docker else "",
            "isolation": trustdiff_runner.isolation_class(runtime) if docker else ""}


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    path.write_bytes(raw.encode("utf-8", "backslashreplace"))


def ensure_safe_state() -> None:
    """Never follow agent-created state symlinks into a verifier host."""
    if not STATE.is_absolute() and STATE != ROOT / ".trustdiff":
        raise ValueError("TRUSTDIFF_STATE_DIR must be an absolute path")
    candidates = [STATE, STATE / "evidence", STATE / "challenges", STATE / "ledger.jsonl", STATE / "ledger.anchor.json", STATE / "latest.json", STATE / "config.json"]
    for item in candidates:
        if item.is_symlink():
            raise ValueError(f"Unsafe verification state symlink: {item}")
    # Absolute state path must not point back through a symlink into the candidate repo.
    if STATE.resolve() != STATE.absolute():
        raise ValueError("Verification state path resolves through a symlink")
    if STATE == ROOT:
        raise ValueError("Verification state cannot be the repository root")
    rc, tracked, _ = git("ls-files", "-z", "--", ".trustdiff")
    if not rc and tracked:
        raise ValueError("Candidate repository tracks .trustdiff artifacts; refuse agent-controlled state")


def init_cmd(_: argparse.Namespace) -> int:
    ensure_safe_state()
    STATE.mkdir(exist_ok=True)
    config = STATE / "config.json"
    if not config.exists():
        save_json(config, {"version": 1, "baseline": "HEAD", "contracts": "trustdiff.contracts.json"})
    print(f"Initialized TrustDiff in {STATE}")
    return 0


def _resolve_commit(ref: str) -> str:
    rc, out, err = git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
    if rc:
        raise ValueError(f"Invalid baseline commit: {err.strip()}")
    return out.strip()


def _tracked_baseline_policy(path: Path, baseline: str, target: str) -> tuple[list[dict[str, Any]], str, str, bool, list[str]]:
    """Never silently select a policy newly supplied by an untrusted PR."""
    if not trustdiff_safe.clean_repo_path(path.as_posix()) or path.drive:
        raise ValueError("Contract path must be inside the repository and relative")
    object_path = path.as_posix()
    rc, old, _ = trustdiff_safe.run_git_bytes(ROOT, "show", f"{baseline}:{object_path}", max_output=1_000_000)
    if rc in (124, 125, 126, 127):
        raise ValueError("Baseline contract policy is unreadable or exceeds 1 MB")
    rc_target, candidate, _ = trustdiff_safe.run_git_bytes(ROOT, "show", f"{target}:{object_path}", max_output=1_000_000)
    current = ""
    if rc:
        if not rc_target:
            current = candidate.decode("utf-8")
        elif rc_target not in (124, 125, 126, 127):
            local = ROOT / path
            if local.exists() or local.is_symlink():
                if local.resolve() != local.absolute():
                    raise ValueError("Contract policy cannot traverse a symlink")
                current = trustdiff_safe.read_regular_text(local, 1_000_000)
                if current is None:
                    raise ValueError("Contract policy is unreadable or exceeds 1 MB limit")
    drift = rc == 0 and (rc_target != 0 or old != candidate)
    source = "baseline" if rc == 0 and baseline != target else "committed" if rc == 0 else "untrusted"
    data_raw = old.decode("utf-8") if rc == 0 else current
    if len(data_raw.encode("utf-8")) > 1_000_000:
        raise ValueError("Contract policy exceeds 1 MB")
    data = json.loads(data_raw) if data_raw else {"contracts": []}
    if not isinstance(data, dict) or not isinstance(data.get("contracts"), list):
        raise ValueError("Contract file must contain a contracts array")
    contracts = data["contracts"]
    validate_contracts(contracts)
    messages = []
    if source == "untrusted":
        messages.append("No committed baseline contract policy exists: bootstrap via a reviewed commit before allowing success")
    if drift:
        messages.append("Contracts differ from the trusted baseline; baseline contracts were enforced, but policy mutation requires a separate reviewed change")
    return contracts, source, sha256_bytes(data_raw.encode("utf-8")), drift, messages


def _clean_worktree() -> bool:
    # Never pass attestations for a tree that differs from the declared target commit.
    return trustdiff_runner.clean_candidate(ROOT, STATE) is True


def _verify_external_pin(args: argparse.Namespace) -> None:
    if not args.verifier_sha256:
        return
    import trustdiff_supply
    if trustdiff_supply.verifier_digest() != args.verifier_sha256:
        raise ValueError("Running verifier differs from the approved SHA-256")
    if not args.baseline or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", args.baseline):
        raise ValueError("An independent check needs an externally approved full baseline commit ID")
    if STATE.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("An independent check needs a verifier-owned state directory outside the candidate")
    if args.allow_host_execution or os.environ.get("TRUSTDIFF_TRUST_GIT_CONFIG") == "1":
        raise ValueError("Host execution and config overrides are unavailable for independent checks")
    if args.runner == "docker" and not trustdiff_runner.image_is_pinned(args.image):
        raise ValueError("An independent check needs a digest-pinned runner image")


def check_cmd(args: argparse.Namespace, quiet: bool = False) -> int:
    try:
        if getattr(args, "verifier_sha256", None):
            _verify_external_pin(args)
        ensure_safe_state()
        trustdiff_safe.require_safe_git_config(ROOT)
        STATE.mkdir(parents=True, exist_ok=True)
        target = git_head()
        baseline = _resolve_commit(args.baseline or target)
        existing_ledger = STATE / "ledger.jsonl"
        if existing_ledger.exists() and not verify_ledger()["valid"]:
            raise ValueError("Prior evidence ledger is corrupt; preserve it for investigation before continuing")
        before = repo_digest()
        worktree_before = worktree_digest()
        snapshot = input_snapshot()
        clean_before = _clean_worktree()
        files = changed_files(baseline, target) if baseline != target else []
        contracts, policy_source, policy_sha, drift, policy_errors = _tracked_baseline_policy(Path(args.contracts), baseline, target)
        required_contracts = [c for c in contracts if c.get("required", True)]
        runner_mode = "host" if args.allow_host_execution else args.runner
        lfs_cache = Path(args.lfs_cache) if getattr(args, "lfs_cache", None) else None
        results, evidence = [], []
        for contract in contracts:
            result, ev = evaluate_contract(contract, baseline, target, runner_mode, args.image, getattr(args, "require_pinned_image", False), getattr(args, "runtime", None), lfs_cache)
            results.append(asdict(result)); evidence.append(asdict(ev))
        runtime = getattr(args, "runtime", None)
        challenge_candidates = trustdiff_challenge.discover(ROOT, files, target) if args.challenge_mode != "off" else []
        generated_challenges = trustdiff_challenge.write(ROOT, challenge_candidates, STATE) if challenge_candidates else []
        if args.challenge_mode == "run":
            for challenge, candidate in zip(generated_challenges, challenge_candidates):
                started = now()
                if runner_mode == "docker" and getattr(args, "require_pinned_image", False) and not trustdiff_runner.image_is_pinned(args.image):
                    verdict, explanation, details = "ERROR", "Counterexample runner image must be pinned by digest", {}
                else:
                    verdict, explanation, details = trustdiff_challenge.evaluate(
                        candidate["case"], ROOT, baseline, target, runner_mode, args.image, 30, runtime, lfs_cache
                    )
                output = json.dumps(details, sort_keys=True)
                ev_id = "E-" + sha256_bytes((challenge["id"] + started + output).encode())[:16]
                metadata = runner_metadata(runner_mode, args.image, runtime)
                evidence.append(asdict(Evidence(ev_id, challenge["id"], "challenge", sha256_bytes(candidate["script"].encode()), f"trustdiff/{VERSION}", env_info(), None, output, started, now(), [challenge["assumption"], "Heuristic oracle; reviewed policy is required for coverage"], metadata)))
                if verdict != "UNKNOWN":
                    results.append(asdict(Result(challenge["id"], verdict, [ev_id], baseline, target, f"trustdiff/{VERSION}", explanation, [challenge["assumption"]])))
                challenge["status"] = verdict
        after = repo_digest()
        worktree_after = worktree_digest()
        clean_after = _clean_worktree()
        integrity = "PASS" if before == after and worktree_before == worktree_after and clean_before == clean_after and git_head() == target else "FAIL"
        claims = verify_claims(Path(args.claims), results) if args.claims else []
        risks = trustdiff_impact.risk_topics(files)
        for detected in trustdiff_impact.risk_from_patch(ROOT, baseline, target, files):
            if not any(x["path"] == detected["path"] and x["topic"] == detected["topic"] for x in risks):
                risks.append(detected)
        impact = trustdiff_impact.impact_graph(ROOT, files)
        gaps = trustdiff_impact.coverage_gaps(risks, contracts, results)
        weakening = trustdiff_impact.test_weakening(ROOT, baseline, target, files)
        guard_reasons = list(policy_errors)
        if not clean_before or not clean_after:
            guard_reasons.append("Working tree differs from the declared target Git commit; commit or discard changes before a trusted check")
        if not required_contracts:
            guard_reasons.append("No required contracts were loaded; TrustDiff refuses to report a successful verification without an obligation to verify")
        critical_gaps = [g for g in gaps if g["level"] == "critical"]
        if critical_gaps:
            guard_reasons.append(f"{len(critical_gaps)} critical risk(s) lack an explicit passing contract (coverage is fail-closed)")
        guard = {"verdict": "ERROR", "explanation": "; ".join(guard_reasons)} if guard_reasons else None
        pass_checks = bool(results) and all(r["verdict"] == "PASS" for r in results)
        pass_claims = all(c["verdict"] == "PASS" for c in claims)
        overall = "PASS" if guard is None and integrity == "PASS" and pass_checks and pass_claims else "FAIL"
        report = {
            "schema_version": 2,
            "checker_version": VERSION,
            "generated_at": now(),
            "baseline_commit": baseline,
            "target_commit": target,
            "repository_fingerprint": before,
            "worktree_fingerprint_before": worktree_before,
            "worktree_fingerprint_after": worktree_after,
            "clean_worktree": clean_before and clean_after,
            "input_snapshot": snapshot,
            "integrity_verdict": integrity,
            "overall_verdict": overall,
            "changed_files": files,
            "risk_plan": risk_plan(files),
            "risk_topics": risks,
            "impact": impact,
            "coverage_gaps": gaps,
            "test_weakening": weakening,
            "challenge_recipes": trustdiff_impact.challenge_recipes(files, risks),
            "generated_challenges": generated_challenges,
            "semantic_hypotheses": semantic_hypotheses(baseline, target),
            "policy_source": policy_source,
            "policy_path": args.contracts,
            "policy_sha256": policy_sha,
            "policy_drift": drift,
            "runner_config": runner_metadata(runner_mode, args.image, runtime),
            "git_config_audit": "overridden" if os.environ.get("TRUSTDIFF_TRUST_GIT_CONFIG") == "1" else "clean",
            "unusual_paths": [f["path"] for f in files if not trustdiff_safe.clean_repo_path(f["path"])][:50],
            "verification_guard": guard,
            "results": results,
            "claims": claims,
            "evidence": evidence,
            "limitations": [
                "Passing contracts support only the declared obligations, not universal absence of bugs",
                "Impact graph sees static imports only; dynamic dependencies and service calls are not modeled",
                "Risk hypotheses and suggested challenges are unexecuted until independent contracts run",
                "Worktree snapshot excludes Git-ignored inputs and external services",
                "Docker shares a host kernel; only a trusted isolated verifier and externally managed signer establish operational independence",
                "The local SHA-256 ledger is tamper-evident, not a standalone cryptographic trust anchor",
            ],
        }
        repository = getattr(args, "repository", None)
        if repository:
            if not trustdiff_proof.valid_repository(repository):
                raise ValueError("Repository must be a valid owner/name")
            report["repository"] = repository.lower()
        report_bytes = trustdiff_proof.report_bytes(report)
        if len(report_bytes) > trustdiff_proof.MAX_JSON // 2:
            raise ValueError("Evidence exceeds the portable report limit")
        report_hash = sha256_bytes(report_bytes)
        archive = STATE / "evidence" / f"{report_hash}.json"
        archive.parent.mkdir(parents=True, exist_ok=True)
        if archive.exists() or archive.is_symlink():
            if not trustdiff_safe.is_regular_file(archive) or trustdiff_safe.read_regular_text(archive, trustdiff_proof.MAX_JSON) is None or archive.read_bytes() != report_bytes:
                raise ValueError("Archived report path is already occupied")
        else:
            with archive.open("xb") as handle:
                handle.write(report_bytes)
        ledger_hash = append_ledger({"record_type": "verification", "generated_at": report["generated_at"], "report_hash": report_hash, "baseline_commit": baseline, "target_commit": target, "integrity_verdict": integrity, "overall_verdict": overall})
        save_json(STATE / "latest.json", report)
        if not quiet:
            print(json.dumps({"overall_verdict": overall, "integrity_verdict": integrity, "verification_guard": guard, "contracts": len(results), "coverage_gaps": len(gaps), "claims": len(claims), "ledger_entry": ledger_hash, "report": str(STATE / "latest.json")}, indent=2))
        return 0 if overall == "PASS" else 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def _markdown_summary(report: dict[str, Any]) -> str:
    # Escape Markdown metacharacters to avoid untrusted PR titles/content poisoning summaries.
    def safe(value: Any) -> str:
        return re.sub(r"([\\`*_{}\[\]<>|])", r"\\\1", str(value)).replace("\n", " ").replace("@", "@\u200b")[:500]
    parts = ["# TrustDiff verification", "", f"**Verdict:** {safe(report.get('overall_verdict', 'UNKNOWN'))}", "", f"**Commit:** `{safe(report.get('target_commit', ''))}`", "", "| Contract | Verdict | Explanation |", "|---|---|---|"]
    for r in report.get("results", []):
        parts.append(f"| {safe(r.get('contract_id'))} | {safe(r.get('verdict'))} | {safe(r.get('explanation'))} |")
    parts += ["", f"**Coverage gaps:** {len(report.get('coverage_gaps', []))}", "", "**Limitations:** This verifies listed obligations only. Challenge recipes are not executed evidence."]
    for gap in report.get("coverage_gaps", [])[:25]:
        parts.append(f"- {safe(gap.get('level'))}: {safe(gap.get('path'))} / {safe(gap.get('topic'))}")
    return "\n".join(parts) + "\n"


def _sarif(report: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for gap in report.get("coverage_gaps", []):
        findings.append(("TD-COVERAGE", f"{gap.get('topic')} change has no passing covered contract", gap.get("path"), "error" if gap.get("level") == "critical" else "warning"))
    for suspect in report.get("test_weakening", []):
        findings.append(("TD-TEST-DRIFT", suspect.get("message"), suspect.get("path"), "warning"))
    for result in report.get("results", []):
        if result.get("verdict") != "PASS":
            findings.append(("TD-CONTRACT", f"{result.get('contract_id')}: {result.get('verdict')} — {result.get('explanation')}", None, "error"))
    data = []
    for rule, msg, path, level in findings:
        finding = {"ruleId": rule, "level": level, "message": {"text": msg}}
        if path:
            finding["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path}}}]
        data.append(finding)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "TrustDiff", "version": VERSION, "rules": [{"id": r} for r in ("TD-COVERAGE", "TD-TEST-DRIFT", "TD-CONTRACT")]}}, "results": data}]}


def _coerce_report(report: Any) -> dict[str, Any]:
    """Reports can come from CI artifacts: render defensively, never crash on odd types."""
    if not isinstance(report, dict):
        raise ValueError("Report is not a JSON object")
    fixed = dict(report)
    for key in ("results", "claims", "coverage_gaps", "test_weakening", "semantic_hypotheses"):
        value = fixed.get(key, [])
        fixed[key] = [i for i in value if isinstance(i, dict)] if isinstance(value, list) else []
    if not isinstance(fixed.get("limitations", []), list):
        fixed["limitations"] = []
    return fixed


def report_cmd(args: argparse.Namespace) -> int:
    path = Path(args.input)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Report exceeds the 20 MiB rendering limit")
    report = _coerce_report(trustdiff_proof._read_json(path))
    if args.format == "json":
        rendered = json.dumps(report, indent=2, ensure_ascii=False)
    elif args.format == "markdown":
        rendered = _markdown_summary(report)
    elif args.format == "sarif":
        rendered = json.dumps(_sarif(report), indent=2, ensure_ascii=False)
    else:
        rows = "".join(f"<tr><td>{html.escape(str(r.get('contract_id')))}</td><td><b>{html.escape(str(r.get('verdict')))}</b></td><td>{html.escape(str(r.get('explanation')))}</td></tr>" for r in report.get("results", []))
        claims = "".join(f"<li><b>{html.escape(str(c.get('claim_id')))}</b>: {html.escape(str(c.get('verdict')))}</li>" for c in report.get("claims", []))
        gaps = "".join(f"<li>{html.escape(str(g.get('level')))}: {html.escape(str(g.get('path')))} — {html.escape(str(g.get('topic')))}</li>" for g in report.get("coverage_gaps", []))
        hypotheses = "".join(f"<li>{html.escape(str(h.get('message')))}</li>" for h in report.get("semantic_hypotheses", []))
        rendered = f"<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>TrustDiff report</title><style>body{{font:15px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#182334}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ccd3db;padding:.7rem;text-align:left}}b{{font-family:monospace}}.status{{border-left:5px solid #354e75;padding:1rem;background:#f4f7fb}}</style><h1>TrustDiff / Independent verification</h1><div class='status'><h2>Verdict: {html.escape(str(report.get('overall_verdict','UNKNOWN')))}</h2><p>Integrity: {html.escape(str(report.get('integrity_verdict','UNKNOWN')))}</p><p>{html.escape(str(report.get('baseline_commit','')))} → {html.escape(str(report.get('target_commit','')))}</p></div><h2>Obligations</h2><table><tr><th>Contract</th><th>Verdict</th><th>Explanation</th></tr>{rows}</table><h2>Unverified risks</h2><ul>{gaps or '<li>No classified uncovered risks</li>'}</ul><h2>Agent claims</h2><ul>{claims or '<li>None supplied</li>'}</ul><h2>Hypotheses (not proof)</h2><ul>{hypotheses or '<li>None detected</li>'}</ul><h2>Limitations</h2><ul>{''.join('<li>'+html.escape(str(x))+'</li>' for x in report.get('limitations', []))}</ul>"
    if args.format == "json" and args.output is None:
        print(rendered)
    else:
        dest = Path(args.output or (str(STATE / "report.") + {"markdown": "md", "sarif": "sarif", "html": "html", "json": "json"}[args.format]))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""), encoding="utf-8")
        print(dest)
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trustdiff", description="Evidence-first independent code verification")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init").set_defaults(func=init_cmd)
    c = sub.add_parser("check")
    c.add_argument("--baseline", help="Trusted base commit; policy is loaded from this commit")
    c.add_argument("--contracts", default="trustdiff.contracts.json")
    c.add_argument("--repository", help="Owner/name supplied by the verifier for signed repository binding")
    c.add_argument("--verifier-sha256", help="Enforce an externally approved verifier digest and an external state directory")
    c.add_argument("--claims", default="", help="JSON file containing agent claims")
    c.add_argument("--runner", choices=["none", "docker"], default="none", help="Fail-closed by default; Docker has restricted execution")
    c.add_argument("--image", default="python:3.11-slim", help="Docker image; use @sha256: digest for attestable results")
    c.add_argument("--runtime", choices=sorted(trustdiff_runner.ALLOWED_RUNTIMES), help="Stronger isolation: run containers under gVisor (runsc) or a Kata Containers microVM runtime that is already registered with Docker. Fails closed if unavailable.")
    c.add_argument("--require-pinned-image", action="store_true", help="Refuse to execute tests unless --image is pinned by @sha256 digest (use in CI)")
    c.add_argument("--lfs-cache", help="Approved object directory outside the candidate, for offline Git LFS hydration")
    c.add_argument("--allow-host-execution", action="store_true", help="DANGEROUS: local testing only; prevents signing")
    c.add_argument("--challenge-mode", choices=["off", "generate", "run"], default="generate", help="Generate narrow executable admin-role countertests; run only in selected runner")
    c.set_defaults(func=check_cmd)
    r = sub.add_parser("report")
    r.add_argument("--input", default=str(STATE / "latest.json"))
    r.add_argument("--format", choices=["json", "html", "markdown", "sarif"], default="json")
    r.add_argument("--output", default=None)
    r.set_defaults(func=report_cmd)
    v = sub.add_parser("verify-ledger")
    v.set_defaults(func=verify_ledger_cmd)
    trustdiff_proof.add_commands(sub)
    trustdiff_repair.add_commands(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
