"""Deterministic synthetic baseline/challenger comparison across four domains."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import trustdiff_challenge as challenge


# An existing smoke check verifies the positive path. Boundary probes exercise
# the extra input or repeated operation that distinguishes each mutant.
FIXTURES = (
    ("authorization", ["admin", "user"], [True, False], "return key == 'admin'", "return True"),
    ("money", ["id", "id"], [True, False], "return key not in seen and not seen.add(key)", "return True"),
    ("database", ["up", "rollback"], [{"rows": 1}, {"rows": 1}], "return {'rows': 1}",
     "return {'rows': int(key == 'up')}"),
    ("api", ["v2", "v1"], [200, 200], "return 200", "return 200 if key == 'v2' else 404"),
)


def commit(root: Path) -> str:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root).strip().decode()

    git("add", "-A")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "fixture")
    return git("rev-parse", "HEAD")


def benchmark() -> dict:
    rows = []
    for domain, inputs, expected, good, bad in FIXTURES:
        with tempfile.TemporaryDirectory(prefix="trustdiff-bench-") as parent:
            root = Path(parent)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            path = root / "fixture.py"
            path.write_text(f"seen = set()\ndef check(key):\n    {good}\n", encoding="utf-8")
            baseline = commit(root)
            for name, code in (("control", good), ("mutant", bad)):
                path.write_text(f"seen = set()\ndef check(key):\n    {code}\n", encoding="utf-8")
                target = commit(root)
                case = {"domain": domain, "path": path.name, "expected": expected,
                        "calls": [{"function": "check", "args": [value]} for value in inputs]}
                row = {"domain": domain, "variant": name, "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for key, spec in (("smoke", {**case, "calls": case["calls"][:1], "expected": expected[:1]}), ("boundary", case)):
                    start = time.perf_counter()
                    verdict, _, _ = challenge.evaluate(spec, root, baseline, target, "host", "", 10)
                    row[key] = {"verdict": verdict, "seconds": round(time.perf_counter() - start, 3)}
                rows.append(row)
    return {"protocol": "trustdiff.synthetic-benchmark/v1", "execution": "host, generated fixtures", "rows": rows,
            "additional_mutants_detected": sum(r["variant"] == "mutant" and r["smoke"]["verdict"] == "PASS" and r["boundary"]["verdict"] == "FAIL" for r in rows),
            "control_failures": sum(r["variant"] == "control" and r["boundary"]["verdict"] != "PASS" for r in rows)}


if __name__ == "__main__":
    result = benchmark()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["additional_mutants_detected"] == len(FIXTURES) and not result["control_failures"] else 1)
