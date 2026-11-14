#!/usr/bin/env python3
"""Adversarial illustration; uses explicitly UNSAFE host execution in temporary fixture.

The Docker runner is the real recommended execution mode; this fixture only proves
that the independent checker detects the regression without needing Docker.
"""
from __future__ import annotations
import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "def can_access_admin(role):\n    return role == 'admin'\n"
TARGET = "def can_access_admin(role):\n    return role != 'guest'\n"
WEAK = "from app import can_access_admin\nassert can_access_admin('admin') is True\nprint('weak agent tests: PASS')\n"
INDEPENDENT = "from app import can_access_admin\nassert can_access_admin('admin') is True\nassert can_access_admin('user') is False, 'non-admin gained admin access'\nassert can_access_admin('guest') is False\nprint('independent authorization contract: PASS')\n"
CONTRACTS = {"version": 2, "contracts": [{"id": "AUTH-REGRESSION-001", "description": "Only admins may access admin route", "type": "test", "command": ["python3", "independent_verifier.py"], "timeout_seconds": 10, "covers": ["authorization"]}]}


def sh(cwd: Path, *cmd: str, check: bool = True):
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=check)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="trustdiff-security-") as td:
        repo = Path(td)
        sh(repo, "git", "init", "-q", "-b", "main")
        (repo / ".gitignore").write_text(".trustdiff/\n")
        (repo / "app.py").write_text(BASELINE)
        (repo / "independent_verifier.py").write_text(INDEPENDENT)
        (repo / "trustdiff.contracts.json").write_text(json.dumps(CONTRACTS, indent=2))
        sh(repo, "git", "add", ".")
        sh(repo, "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "trusted authorization baseline")
        baseline = sh(repo, "git", "rev-parse", "HEAD").stdout.strip()
        (repo / "app.py").write_text(TARGET)
        (repo / "weak_agent_tests.py").write_text(WEAK)
        sh(repo, "git", "add", ".")
        sh(repo, "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "agent implementation")
        target = sh(repo, "git", "rev-parse", "HEAD").stdout.strip()
        weak = sh(repo, sys.executable, "weak_agent_tests.py", check=False)
        verifier = sh(repo, sys.executable, "independent_verifier.py", check=False)
        checked = sh(repo, sys.executable, str(ROOT / "trustdiff.py"), "check", "--baseline", baseline, "--contracts", "trustdiff.contracts.json", "--challenge-mode", "run", "--allow-host-execution", check=False)
        report = json.loads((repo / ".trustdiff/latest.json").read_text())
        counter = next((r for r in report["results"] if r["contract_id"].startswith("CHALLENGE-ADMIN")), None)
        result = {"baseline": baseline, "target": target, "weak_agent_tests_exit": weak.returncode, "independent_verifier_exit": verifier.returncode, "trustdiff_verdict": report["results"][0]["verdict"], "generated_challenge_verdict": counter["verdict"] if counter else "MISSING", "overall_verdict": report["overall_verdict"], "policy_source": report["policy_source"], "evidence": report["evidence"][0]["evidence_id"], "limitation": "Host execution is intentionally used ONLY inside this locally generated fixture; it is not independent isolation."}
        print(json.dumps(result, indent=2))
        return 0 if weak.returncode == 0 and verifier.returncode != 0 and result["trustdiff_verdict"] == "FAIL" and result["generated_challenge_verdict"] == "FAIL" and result["policy_source"] == "baseline" else 1


if __name__ == "__main__":
    raise SystemExit(main())
