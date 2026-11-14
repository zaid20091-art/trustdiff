"""Static impact analysis, risk coverage and test-drift signals (no code execution)."""
from __future__ import annotations
import ast
import json
import re
import subprocess
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from typing import Any

import trustdiff_safe

TOPICS = {
    "authorization": ("critical", ("auth", "permission", "rbac", "access", "role", "acl", "oauth", "identity"), "Positive/negative access-boundary tests"),
    "money": ("critical", ("payment", "billing", "invoice", "checkout", "transaction", "accounting", "wallet"), "Accounting and double-charge invariants"),
    "secrets_ci": ("critical", (".github/workflows/", "secret", "credential", "token", "terraform", "iam", "infra/", "k8s/"), "Protected workflow and permission checks"),
    "database": ("high", ("migration", "schema", "prisma", "database"), "Migration rollback and data preservation"),
    "dependencies": ("high", ("requirements", "poetry.lock", "pdm.lock", "uv.lock", "package-lock.json", "pnpm-lock", "cargo.lock"), "Dependency change review"),
}
SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}


MAX_PATCH_FILES = 500


def _git(root: Path, *args: str) -> tuple[int, str]:
    rc, out, err = trustdiff_safe.run_git(root, *args)
    return rc, out if rc == 0 else err


def _tracked_files(root: Path) -> list[str]:
    rc, out, _ = trustdiff_safe.run_git_bytes(root, "ls-files", "-z")
    if rc:
        return []
    return [x.decode(errors="surrogateescape") for x in out.split(b"\0") if x]


def file_patch(root: Path, baseline: str, target: str, path: str) -> tuple[list[str], list[str]] | None:
    """(added, removed) lines for exactly one literal path. Per-file diffs avoid parsing 'diff --git a/x b/y' headers,
    which a crafted file name such as 'a b/c.py' can mislead. None means the diff could not be read."""
    rc, out, _ = trustdiff_safe.run_git(root, "diff", "--unified=0", "--no-ext-diff", "--no-textconv", baseline, target, "--", f":(literal){path}")
    if rc:
        return None
    added = [l[1:] for l in out.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = [l[1:] for l in out.splitlines() if l.startswith("-") and not l.startswith("---")]
    return added, removed


def _python_imports(path: str, content: str, known: set[str], status: list[str] | None = None) -> set[str]:
    found: set[str] = set()
    try:
        tree = ast.parse(content, filename=path)
    except SyntaxError:
        if status is not None: status.append("syntax_error")
        return found
    except (ValueError, UnicodeError, RecursionError, MemoryError):  # hostile nesting / NUL bytes must degrade, not crash the gate
        if status is not None: status.append("unparseable")
        return found
    parts = PurePosixPath(path).parts[:-1]
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            prefix = parts[:max(0, len(parts) - node.level + 1)] if node.level else ()
            base = ".".join(prefix + tuple((node.module or "").split("."))) if node.level else (node.module or "")
            modules = [base] + [base + "." + alias.name for alias in node.names]
        for module in modules:
            rel = module.replace(".", "/")
            for cand in (rel + ".py", rel + "/__init__.py"):
                if cand in known:
                    found.add(cand)
    return found


_JS_REF = re.compile(r"(?:\bfrom|\bimport\s*\(|\brequire\s*\()\s*['\"](\.[^'\"\n]{1,2048})['\"]")


def _javascript_imports(path: str, content: str, known: set[str]) -> set[str]:
    found: set[str] = set()
    for ref in _JS_REF.findall(content):
        base = str(PurePosixPath(path).parent.joinpath(ref))
        # PurePosixPath does not collapse '..'; normalize without touching filesystem.
        segments: list[str] = []
        for segment in PurePosixPath(base).parts:
            if segment == "..":
                if segments: segments.pop()
            elif segment != ".":
                segments.append(segment)
        normalized = "/".join(segments)
        for cand in [normalized] + [normalized + suffix for suffix in SOURCE_SUFFIXES] + [normalized + "/index" + suffix for suffix in SOURCE_SUFFIXES]:
            if cand in known:
                found.add(cand)
    return found


def impact_graph(root: Path, changed: list[dict[str, str]], maximum_files: int = 3000) -> dict[str, Any]:
    tracked = [p for p in _tracked_files(root) if Path(p).suffix in SOURCE_SUFFIXES]
    if len(tracked) > maximum_files:
        return {"affected_files": [], "affected_tests": [], "edges": [], "incomplete": True, "reason": f"File limit {maximum_files} exceeded"}
    known = set(tracked)
    reverse: dict[str, set[str]] = defaultdict(set)
    edges: list[dict[str, str]] = []
    skipped = 0
    for src in tracked:
        file = root / src
        content = trustdiff_safe.read_regular_text(file)
        if content is None:
            skipped += 1; continue
        status: list[str] = []
        references = _python_imports(src, content, known, status) if src.endswith(".py") else _javascript_imports(src, content, known)
        if status:
            skipped += 1
        for dep in sorted(references):
            reverse[dep].add(src)
            edges.append({"from": src, "to": dep})
    seeds = sorted({item["path"] for item in changed})
    if any(PurePosixPath(p).name in {"pyproject.toml", "package.json", "tsconfig.json", "requirements.txt", "package-lock.json", "pnpm-lock.yaml"} for p in seeds):
        seeds += [p for p in tracked if p.startswith("tests/") or p.startswith("test/") or ".test." in p]
    queue = deque((p, 0) for p in seeds)
    visited = set(seeds)
    while queue:
        dep, distance = queue.popleft()
        if distance >= 12: continue
        for consumer in sorted(reverse.get(dep, ())):
            if consumer not in visited:
                visited.add(consumer)
                queue.append((consumer, distance + 1))
    affected = sorted(visited)
    tests = [p for p in affected if p.startswith(("tests/", "test/", "spec/")) or p.endswith("_test.py") or Path(p).name.startswith("test_") or ".test." in p or ".spec." in p]
    return {"affected_files": affected[:300], "affected_tests": tests[:150], "edges": edges[:3000], "incomplete": bool(skipped or len(affected) > 300 or len(edges) > 3000), "skipped_files": skipped, "method": "Static imports only; dynamic imports, reflection and runtime service calls are not modeled"}


def risk_topics(changed: list[dict[str, str]]) -> list[dict[str, Any]]:
    risks = []
    for item in changed:
        p = item["path"].lower()
        for topic, (level, needles, obligation) in TOPICS.items():
            if any(n in p for n in needles):
                risks.append({"path": item["path"], "topic": topic, "level": level, "suggested_evidence": obligation})
    return risks


def risk_from_patch(root: Path, baseline: str, target: str, changed: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Detect security-sensitive *content* even in innocently named source files."""
    relevant = sorted({x["path"] for x in changed if Path(x["path"]).suffix in SOURCE_SUFFIXES})
    if not relevant:
        return []
    patterns = {
        "authorization": r"\b(admin|is_admin|role|permission|authorize|access_control|can_access_admin|jwt)\b",
        "money": r"\b(charge|payment|transfer|balance|invoice|currency)\b",
        "secrets_ci": r"\b(secret_key|api_key|token|credential|subprocess\.run|os\.system)\b",
    }
    out: list[dict[str, Any]] = []
    unreadable = 0
    for path in relevant[:MAX_PATCH_FILES]:
        patch = file_patch(root, baseline, target, path)
        if patch is None:
            unreadable += 1
            continue
        content = "\n".join(patch[0] + patch[1])[:2_000_000]
        for topic, pattern in patterns.items():
            if re.search(pattern, content, re.I):
                level, _, suggestion = TOPICS[topic]
                out.append({"path": path, "topic": topic, "level": level, "suggested_evidence": suggestion, "trigger": "changed code content heuristic"})
    if unreadable or len(relevant) > MAX_PATCH_FILES:
        out.append({"path": "<patch-analysis>", "topic": "analysis_incomplete", "level": "high", "suggested_evidence": f"Content analysis skipped {unreadable + max(0, len(relevant) - MAX_PATCH_FILES)} file(s); review manually", "trigger": "analysis limit"})
    return out


def coverage_gaps(risks: list[dict[str, Any]], contracts: list[dict[str, Any]], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {r["contract_id"]: r["verdict"] for r in results}
    gaps = []
    for r in risks:
        matching = [c["id"] for c in contracts if c.get("required", True) and r["topic"] in c.get("covers", [])]
        passing = [cid for cid in matching if by_id.get(cid) == "PASS"]
        if not passing:
            gaps.append({**r, "contracts": matching, "status": "UNVERIFIED", "reason": "No mandatory passing contract explicitly covers this risk"})
    return gaps


def _is_test_path(path: str) -> bool:
    return path.startswith(("test/", "tests/", "spec/")) or path.endswith("_test.py") or ".test." in path or ".spec." in path


_ASSERTION = re.compile(r"\bassert\b|\bexpect\s*\(|\btest\s*\(")


def test_weakening(root: Path, baseline: str, target: str, changed: list[dict[str, str]]) -> list[dict[str, Any]]:
    suspects: list[dict[str, Any]] = []
    examined = 0
    for item in changed:
        path = item["path"]
        if not _is_test_path(path):
            continue
        if item["status"].startswith("D"):
            suspects.append({"path": path, "severity": "high", "kind": "test_deleted", "message": "A test file was removed; review contract coverage"})
            continue
        examined += 1
        if examined > MAX_PATCH_FILES:
            suspects.append({"path": "<patch-analysis>", "severity": "medium", "kind": "analysis_incomplete", "message": f"Only the first {MAX_PATCH_FILES} changed test files were examined for weakening"})
            break
        patch = file_patch(root, baseline, target, path)
        if patch is None:
            continue
        added = sum(1 for l in patch[0] if _ASSERTION.search(l))
        removed = sum(1 for l in patch[1] if _ASSERTION.search(l))
        if removed > added:
            suspects.append({"path": path, "severity": "medium", "kind": "assertion_reduction", "message": f"Removed {removed} test assertion(s), added {added}; potential weakening, not a confirmed defect"})
    return suspects


def challenge_recipes(changed: list[dict[str, str]], topics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate concrete counterexample *recipes*, not pretend executable proofs."""
    templates = {
        "authorization": ("Non-privileged role reaches privileged endpoint", ["admin", "member", "guest", "anonymous", "missing/expired token"], "assert denied for every non-admin role; assert admin permitted"),
        "money": ("Retry/duplicate charge counterexample", ["replayed idempotency key", "two simultaneous requests", "currency rounding edge"], "assert at-most-once charge and conserved total"),
        "database": ("Backward-compatibility counterexample", ["old schema reader", "null/missing value", "migration rollback"], "assert preservation of records and compatibility"),
        "secrets_ci": ("Privilege-escalation workflow counterexample", ["fork pull request", "changed workflow permissions", "untrusted script"], "assert no write credential reaches untrusted code"),
        "dependencies": ("Dependency breakage counterexample", ["fresh lockfile install", "runtime compatibility", "dependency checksum"], "assert clean build and pinned dependency resolution"),
    }
    return [{"path": t["path"], "topic": t["topic"], "challenge": templates[t["topic"]][0], "inputs": templates[t["topic"]][1], "oracle": templates[t["topic"]][2], "status": "SUGGESTED_NOT_EXECUTED"} for t in topics]
