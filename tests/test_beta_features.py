"""Attack-oriented regression tests for the independent evidence boundary."""
import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import trustdiff_challenge
import trustdiff_impact
import trustdiff_runner

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(ROOT / "trustdiff.py")]


def call(root, *cmd):
    return subprocess.run([*CLI, *cmd], cwd=root, text=True, capture_output=True)


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def commit(root, name):
    git(root, "add", ".")
    git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", name)
    return git(root, "rev-parse", "HEAD")


def setup_repo(root, contracts=None):
    git(root, "init", "-q", "-b", "main")
    (root / ".gitignore").write_text(".trustdiff/\n")
    contracts = contracts if contracts is not None else {"contracts": [{"id": "STATIC", "type": "deny_pattern", "pattern": "verify\\s*=\\s*False", "required": True}]}
    (root / "trustdiff.contracts.json").write_text(json.dumps(contracts))
    (root / "app.py").write_text("def can_access_admin(role):\n    return role == 'admin'\n")
    return commit(root, "safe base")


class BetaSecurityTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "Optional Ed25519 crypto extra missing")
    def test_signed_proof_and_tamper_replay_wrong_signer(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "repo"; root.mkdir()
            base = setup_repo(root)
            (root / "README.md").write_text("A user guide\n")
            target = commit(root, "documentation")
            check = call(root, "check", "--baseline", base)
            self.assertEqual(check.returncode, 0, check.stderr + check.stdout)
            report = json.loads((root / ".trustdiff/latest.json").read_text())
            self.assertTrue(report["clean_worktree"])
            self.assertEqual(report["overall_verdict"], "PASS")
            key = Path(d) / "signer.pem"
            store = Path(d) / "allowed.json"
            keygen = call(root, "keygen", "--private", str(key), "--allowed-signers", str(store), "--principal", "verifier@example.org")
            self.assertEqual(keygen.returncode, 0, keygen.stderr)
            proof = root / ".trustdiff/proof.json"
            signed = call(root, "attest", "--key", str(key), "--output", str(proof))
            self.assertEqual(signed.returncode, 0, signed.stderr + signed.stdout)
            verify_args = ["verify-proof", "--bundle", str(proof), "--allowed-signers", str(store), "--principal", "verifier@example.org", "--expected-commit", target, "--expected-policy-sha256", report["policy_sha256"]]
            verified = call(root, *verify_args)
            self.assertEqual(verified.returncode, 0, verified.stderr + verified.stdout)
            self.assertNotEqual(call(root, *verify_args[:-1] + ["bad-digest"]).returncode, 0)
            self.assertNotEqual(call(root, *verify_args[:verify_args.index("--expected-commit")+1] + [base]).returncode, 0)
            wrong_principal = verify_args.copy(); wrong_principal[wrong_principal.index("--principal")+1] = "agent@example.org"
            self.assertNotEqual(call(root, *wrong_principal).returncode, 0)
            tampered = json.loads(proof.read_text()); tampered["report"]["overall_verdict"] = "FAIL"
            proof.write_text(json.dumps(tampered))
            self.assertNotEqual(call(root, *verify_args).returncode, 0)

    def test_baseline_contract_prevents_agent_weakening_policy(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); base = setup_repo(root)
            (root / "trustdiff.contracts.json").write_text('{"contracts": []}')
            commit(root, "attempt to erase contracts")
            run = call(root, "check", "--baseline", base)
            self.assertNotEqual(run.returncode, 0, run.stdout)
            report = json.loads((root / ".trustdiff/latest.json").read_text())
            self.assertTrue(report["policy_drift"])
            self.assertEqual(report["results"][0]["contract_id"], "STATIC")
            self.assertEqual(report["policy_source"], "baseline")

    def test_critical_risk_requires_coverage_even_when_weak_test_passes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); base = setup_repo(root)
            (root / "app.py").write_text("def can_access_admin(role):\n    return role != 'guest'\n")
            commit(root, "widen authorization")
            run = call(root, "check", "--baseline", base)
            self.assertEqual(run.returncode, 1, run.stdout)
            report = json.loads((root / ".trustdiff/latest.json").read_text())
            self.assertTrue(any(g["topic"] == "authorization" and g["level"] == "critical" for g in report["coverage_gaps"]))
            self.assertTrue(report["generated_challenges"])
            script = root / report["generated_challenges"][0]["generated_test"]
            self.assertIn('non-admin role', script.read_text())

    def test_generated_counterexample_fails_on_widened_role(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); base = setup_repo(root)
            (root / "app.py").write_text("def can_access_admin(role):\n    return role != 'guest'\n")
            commit(root, "unsafe authorization")
            result = call(root, "check", "--baseline", base, "--challenge-mode", "run", "--allow-host-execution")
            self.assertEqual(result.returncode, 1)
            report = json.loads((root / ".trustdiff/latest.json").read_text())
            challenge = next(r for r in report["results"] if r["contract_id"].startswith("CHALLENGE-ADMIN"))
            self.assertEqual(challenge["verdict"], "FAIL")
            self.assertEqual(report["generated_challenges"][0]["status"], "FAIL")
            self.assertFalse(any(e["method"] == "challenge" and e["runner"]["mode"] == "docker" for e in report["evidence"]))

    def test_static_import_dependents(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); git(root, "init", "-q", "-b", "main")
            (root / "api.py").write_text("x=1\n")
            (root / "service.py").write_text("import api\n")
            (root / "test_service.py").write_text("import service\n")
            commit(root, "base")
            graph = trustdiff_impact.impact_graph(root, [{"path": "api.py", "status": "M"}])
            self.assertIn("test_service.py", graph["affected_tests"])
            self.assertIn("service.py", graph["affected_files"])

    def test_docker_command_defense_in_depth_flags(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d) / "ws"; ws.mkdir()
            args = trustdiff_runner.build_argv("docker", "trustdiff-x", "x", ws, "python@sha256:" + "a" * 64, ["python3", "tests/test.py"])
            for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pull=never"):
                self.assertIn(flag, args)
            self.assertNotIn("sh", args)

    def test_unknown_unsupported_contract_never_passes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); setup_repo(root, {"contracts": [{"id": "UNSUPPORTED", "type": "magic_ai_proof"}]})
            p = call(root, "check")
            self.assertNotEqual(p.returncode, 0)
            report = json.loads((root / ".trustdiff/latest.json").read_text())
            self.assertEqual(report["results"][0]["verdict"], "UNKNOWN")

    def test_report_sarif_and_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); setup_repo(root)
            self.assertEqual(call(root, "check").returncode, 0)
            sarif = root / ".trustdiff/findings.sarif"
            summary = root / ".trustdiff/summary.md"
            self.assertEqual(call(root, "report", "--format", "sarif", "--output", str(sarif)).returncode, 0)
            self.assertEqual(call(root, "report", "--format", "markdown", "--output", str(summary)).returncode, 0)
            self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
            self.assertIn("TrustDiff verification", summary.read_text())

    def test_signing_untrusted_bootstrap_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "repo"; root.mkdir(); git(root, "init", "-q", "-b", "main")
            (root / "trustdiff.contracts.json").write_text('{"contracts":[{"id":"A","type":"deny_pattern","pattern":"bad"}]}')
            git(root, "add", "trustdiff.contracts.json")
            commit(root, "bootstrap")
            # A signed pack cannot be created from a dirty source.
            (root / "new.txt").write_text("not committed")
            self.assertNotEqual(call(root, "check").returncode, 0)
            self.assertNotEqual(call(root, "bundle").returncode, 0)


if __name__ == "__main__":
    unittest.main()
