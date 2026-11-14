"""Narrow, honest counterexample generator for Python role-based admin checks.

Only functions with the exact documented boolean contract `can_access_admin(role)`
are eligible. Anything else is a suggestion, not an executable assertion.
"""
from __future__ import annotations
import ast
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

import trustdiff_safe
import trustdiff_runner

NAMES = {"can_access_admin", "is_admin_role", "has_admin_access"}
DOMAINS = {"authorization", "money", "database", "api"}
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,99}")
MAX_CASE_BYTES = 32_768

# The worker receives inputs and returns observations. The verifier retains the expected values.
WORKER = """\
import importlib.util
import json
import pathlib
import sys

root = pathlib.Path.cwd()
sys.path.insert(0, str(root))
spec_data = json.loads(pathlib.Path(__file__).read_text(encoding="utf-8").splitlines()[-1][2:])
spec = importlib.util.spec_from_file_location("trustdiff_candidate", root / spec_data["path"])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
values = []
for call in spec_data["calls"]:
    function = getattr(module, call["function"])
    values.append(function(*call.get("args", []), **call.get("kwargs", {})))
print(json.dumps({"observed": values}, allow_nan=False, separators=(",", ":")))
"""


def validate_case(case: dict[str, Any]) -> None:
    if not isinstance(case.get("domain"), str) or case["domain"] not in DOMAINS:
        raise ValueError("counterexample requires a supported domain")
    path = case.get("path")
    if not isinstance(path, str) or not path.endswith(".py") or not trustdiff_safe.clean_repo_path(path):
        raise ValueError("counterexample requires a repository-relative Python path")
    calls, expected = case.get("calls"), case.get("expected")
    if not isinstance(calls, list) or not 1 <= len(calls) <= 32 or not isinstance(expected, list) or len(expected) != len(calls):
        raise ValueError("counterexample needs 1–32 calls and an expected value for each call")
    for call in calls:
        if not isinstance(call, dict) or not isinstance(call.get("function"), str) or not IDENTIFIER.fullmatch(call["function"]):
            raise ValueError("invalid counterexample function")
        if set(call) - {"function", "args", "kwargs"} or not isinstance(call.get("args", []), list) or not isinstance(call.get("kwargs", {}), dict):
            raise ValueError("counterexample uses positional and keyword JSON arguments")
    try:
        size = len(json.dumps([calls, expected], allow_nan=False).encode())
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("counterexample values must be finite JSON") from exc
    if size > MAX_CASE_BYTES:
        raise ValueError("counterexample specification exceeds size limit")


def _ordered_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def execute_script(root: Path, commit: str, script: str, mode: str, image: str, timeout: int,
                   runtime: str | None = None, lfs_cache: Path | None = None) -> tuple[int, str, str]:
    if mode not in {"docker", "host"}:
        return 127, "", "No permitted execution runner"
    with tempfile.TemporaryDirectory(prefix="trustdiff-case-") as parent:
        source = Path(parent) / "trustdiff-challenge.py"
        source.write_bytes(script.encode("utf-8"))
        if mode == "docker":
            options = {"lfs_cache": lfs_cache} if lfs_cache is not None else {}
            return trustdiff_runner.run_docker(["python3", "-I", "/trustdiff-challenge.py"], root, image, timeout,
                                               challenge_script=source, commit=commit, runtime=runtime, **options)
        workspace = Path(parent) / "snapshot"
        try:
            trustdiff_runner.export_snapshot(root, commit, workspace, lfs_cache)
        except (OSError, ValueError, RuntimeError) as exc:
            return 127, "", f"Workspace snapshot failed: {exc}"
        result = trustdiff_safe.bounded_run([sys.executable, "-I", str(source)], cwd=workspace, timeout=timeout)
        return result.rc, result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")


def evaluate(case: dict[str, Any], root: Path, baseline: str, target: str, mode: str, image: str, timeout: int,
             runtime: str | None = None, lfs_cache: Path | None = None) -> tuple[str, str, dict[str, Any]]:
    """Use an approved explicit oracle and validate it by replaying the approved baseline first."""
    validate_case(case)
    worker_inputs = json.dumps({"path": case["path"], "calls": case["calls"]}, ensure_ascii=True)
    script = WORKER + "# " + worker_inputs + "\n"
    details = {"domain": case["domain"], "path": case["path"], "calls": case["calls"], "expected": case["expected"],
               "worker_sha256": hashlib.sha256(script.encode()).hexdigest()}
    for phase, revision in (("baseline", baseline), ("target", target)):
        rc, out, err = execute_script(root, revision, script, mode, image, timeout, runtime, lfs_cache)
        run = details[phase] = {"commit": revision, "exit_code": rc}
        if rc != 0:
            run["diagnostic"] = err[-1500:]
            return "ERROR", f"{phase} counterexample worker exited {rc}", details
        try:
            payload = json.loads(out)
            if not isinstance(payload, dict) or set(payload) != {"observed"} or not isinstance(payload["observed"], list):
                raise ValueError("invalid observations")
            observed = payload["observed"]
            serialized = _ordered_json(observed)
            if len(serialized) > MAX_CASE_BYTES:
                raise ValueError("oversized observations")
        except (ValueError, RecursionError):
            return "ERROR", f"{phase} did not return bounded JSON observations", details
        run["observed"] = observed
        if serialized != _ordered_json(case["expected"]):
            verdict = "UNKNOWN" if phase == "baseline" else "FAIL"
            return verdict, f"{phase} observations differ from the approved oracle", details
    return "PASS", "Baseline and candidate satisfy the approved oracle", details


def discover(root: Path, changed: list[dict[str, str]], commit: str | None = None) -> list[dict[str, Any]]:
    generated = []
    for item in changed:
        file = item["path"]
        if not file.endswith(".py") or not trustdiff_safe.clean_repo_path(file): continue
        if commit:
            rc, source, _ = trustdiff_safe.run_git(root, "show", f"{commit}:{file}", max_output=250_000)
            if rc:
                continue
        else:
            source = trustdiff_safe.read_regular_text(root / file, 250_000)
        if source is None: continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, UnicodeError, RecursionError, MemoryError): continue
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.name not in NAMES or node.decorator_list: continue
            args = node.args
            if args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg or args.defaults or args.kw_defaults: continue
            if len(args.args) != 1 or args.args[0].arg != "role": continue
            script = f'''# Heuristic probe. Expected behavior requires reviewer confirmation.
import importlib.util
import pathlib
spec = importlib.util.spec_from_file_location("trustdiff_candidate", pathlib.Path.cwd() / {file!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
check = getattr(module, {node.name!r})
assert check("admin") is True, "admin must be granted"
for role in ("user", "guest", "anonymous", ""):
    assert check(role) is False, f"non-admin role {{role!r}} gained admin rights"
print("TrustDiff counterexample: all boundary roles denied")
'''
            key = hashlib.sha256((file + node.name).encode()).hexdigest()[:12]
            case = {"domain": "authorization", "path": file,
                    "calls": [{"function": node.name, "args": [role]} for role in ("admin", "user", "guest", "anonymous", "")],
                    "expected": [True, False, False, False, False]}
            generated.append({"id": "CHALLENGE-ADMIN-" + key, "path": file, "function": node.name, "script": script, "case": case,
                              "assumption": "Function must take one role string and return a strict boolean"})
            if len(generated) >= 32:
                return generated
    return generated


def write(root: Path, discovered: list[dict[str, Any]], state: Path | None = None) -> list[dict[str, str]]:
    out = (state if state is not None else root / ".trustdiff") / "challenges"
    out.mkdir(parents=True, exist_ok=True)
    result = []
    for item in discovered:
        path = out / (item["id"] + ".py")
        path.write_text(item["script"], encoding="utf-8")
        result.append({"id": item["id"], "source": item["path"], "generated_test": path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path), "assumption": item["assumption"], "status": "GENERATED_NOT_EXECUTED"})
    return result
