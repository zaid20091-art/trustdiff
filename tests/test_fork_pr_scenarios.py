"""P0-02: pull-request scenarios replayed with REAL git repositories and the REAL verifier, exactly as the gate runs it:
the verifier is extracted from the trusted base commit (git archive), pinned by digest, and run with cwd = the candidate.

Contracts are deny_pattern/policy so no Docker is needed. Scenarios that need Docker are in test_runner_hardening.
"""
import json
import io
import os
import shutil
import subprocess
import tarfile
import sys
import tempfile
import unittest
from pathlib import Path

import trustdiff_supply as supply

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = {"version": 2, "contracts": [
    {"id": "DENY-TLS", "type": "deny_pattern", "pattern": "verify\\s*=\\s*False", "covers": []},
]}


def sh(*a, cwd, check=True, **kw):
    return subprocess.run(a, cwd=cwd, text=True, capture_output=True, check=check, **kw)


def commit(repo, msg):
    sh("git", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=T", "-c", "user.email=t@x.invalid", "commit", "-qm", msg, cwd=repo)
    return sh("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()


class ForkEnv(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.addCleanup(self._tmp.cleanup)
        self.base_dir = Path(self._tmp.name).resolve()
        self.upstream = self.base_dir / "upstream"; self.upstream.mkdir()
        sh("git", "init", "-q", "-b", "main", cwd=self.upstream)
        (self.upstream / ".gitattributes").write_text("*.py text eol=lf\n")
        for name in supply.VERIFIER_FILES:
            shutil.copy(ROOT / name, self.upstream / name)
        (self.upstream / "trustdiff.contracts.json").write_text(json.dumps(CONTRACTS))
        (self.upstream / ".github" / "workflows").mkdir(parents=True)
        (self.upstream / ".github" / "workflows" / "trustdiff-gate.yml").write_text("name: gate\n")
        (self.upstream / "app.py").write_text("import requests\nrequests.get(url)\n")
        self.base_sha = commit(self.upstream, "trusted base")
        # the digest an organisation would have approved OUT OF BAND for this base commit
        self.approved = supply.verifier_digest(self.upstream)
        # emulate the workflow: extract the trusted verifier from the BASE commit
        self.verifier = self.base_dir / "trusted"; self.verifier.mkdir()
        archive = subprocess.run(["git", "archive", self.base_sha, *supply.VERIFIER_FILES], cwd=self.upstream, capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
            for name in supply.VERIFIER_FILES:
                with tree.extractfile(name) as member:
                    (self.verifier / name).write_bytes(member.read())
        # the fork and the candidate checkout (the base commit is fetched into it, as refs/pull/N/head would provide)
        self.fork = self.base_dir / "fork"
        shutil.copytree(self.upstream, self.fork)

    def pr(self, files: dict[str, str | None], message="pr"):
        for rel, content in files.items():
            path = self.fork / rel
            if content is None:
                path.unlink(); continue
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content)
        head = commit(self.fork, message)
        self.cand = self.base_dir / "candidate"
        if self.cand.exists(): shutil.rmtree(self.cand)
        shutil.copytree(self.fork, self.cand)
        return head

    def gate(self, *extra, env=None):
        e = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(env or {})}
        return subprocess.run([sys.executable, str(self.verifier / "trustdiff.py"), "check", "--baseline", self.base_sha, *extra], cwd=self.cand, text=True, capture_output=True, env=e)

    def report(self):
        return json.loads((self.cand / ".trustdiff" / "latest.json").read_text())


class VerifierIndependenceTests(ForkEnv):
    def test_clean_change_passes_with_the_trusted_verifier(self):
        self.pr({"app.py": "import requests\nrequests.get(url, timeout=3)\n"})
        p = self.gate(); self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.report()["policy_source"], "baseline")

    def test_pr_that_neuters_the_verifier_cannot_change_the_verdict(self):
        """The PR rewrites trustdiff.py to always pass AND introduces the forbidden pattern. The gate uses the base verifier."""
        neutered = "import sys\nprint('PASS (neutered)')\nsys.exit(0)\n"
        self.pr({"trustdiff.py": neutered, "app.py": "import requests\nrequests.get(url, verify=False)\n"})
        p = self.gate()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual({r["contract_id"]: r["verdict"] for r in self.report()["results"]}["DENY-TLS"], "FAIL")
        # The neutered candidate verifier happily "passes" anything - which is why its OWN output can never be trusted
        # (it would exit 0 for `verifier-digest` too). The digest is computed by independent code (the workflow's inline
        # script / the trusted copy) and the candidate's tree no longer matches the out-of-band approved value.
        lie = subprocess.run([sys.executable, str(self.cand / "trustdiff.py"), "verifier-digest", "--expect", self.approved], cwd=self.cand, capture_output=True, text=True)
        self.assertEqual(lie.returncode, 0)
        self.assertNotEqual(supply.verifier_digest(self.cand), self.approved)

    def test_extracted_base_verifier_matches_the_approved_digest(self):
        self.pr({"app.py": "x = 1\n"})
        self.assertEqual(supply.verifier_digest(self.verifier), self.approved)

    def test_pr_cannot_substitute_a_different_approved_digest(self):
        """The approved digest lives in repository settings, not in a file the PR can edit: a PR-supplied value is ignored by design."""
        self.pr({"verifier.sha256": "0" * 64, "app.py": "x = 1\n"})
        self.assertEqual(supply.verifier_digest(self.verifier), self.approved)
        self.assertNotEqual((self.cand / "verifier.sha256").read_text(), self.approved)

    def test_modified_verifier_in_base_checkout_is_detected(self):
        (self.verifier / "trustdiff_proof.py").write_text((self.verifier / "trustdiff_proof.py").read_text() + "\n# tampered\n")
        p = subprocess.run([sys.executable, str(self.verifier / "trustdiff.py"), "verifier-digest", "--expect", self.approved], capture_output=True, text=True, cwd=self.upstream)
        self.assertEqual(p.returncode, 1)

    def test_shadow_modules_in_the_candidate_are_never_imported(self):
        marker = self.base_dir / "PWNED"
        payload = f"open({str(marker)!r}, 'w').write('x')\n"
        shadows = {f"{m}.py": payload for m in ("trustdiff_impact", "trustdiff_safe", "trustdiff_runner", "json", "re", "hashlib", "sitecustomize", "usercustomize")}
        self.pr({**shadows, "app.py": "x = 2\n"})
        control = subprocess.run([sys.executable, "-c", "import trustdiff_impact"], cwd=self.cand, capture_output=True, text=True)
        self.assertTrue(marker.exists(), "control: the payload must be effective when the candidate directory IS on sys.path")
        marker.unlink()
        p = self.gate(); self.assertIn(p.returncode, (0, 1), p.stdout + p.stderr)      # ran to a verdict, did not crash
        self.assertTrue((self.cand / ".trustdiff" / "latest.json").exists())
        self.assertFalse(marker.exists())


class PolicyAndWorkflowTamperingTests(ForkEnv):
    def test_pr_that_deletes_a_contract_is_judged_by_the_baseline_policy(self):
        self.pr({"trustdiff.contracts.json": json.dumps({"version": 2, "contracts": [{"id": "NOOP", "type": "policy", "match": "nothing/**", "covers": []}]}),
                 "app.py": "import requests\nrequests.get(url, verify=False)\n"})
        p = self.gate()
        self.assertNotEqual(p.returncode, 0)
        report = self.report()
        self.assertTrue(report["policy_drift"]); self.assertEqual(report["policy_source"], "baseline")
        self.assertEqual({r["contract_id"] for r in report["results"]}, {"DENY-TLS"})

    def test_pr_editing_the_gate_workflow_is_a_critical_uncovered_risk(self):
        self.pr({".github/workflows/trustdiff-gate.yml": "name: gate\non: pull_request\njobs: {}\n"})
        p = self.gate()
        self.assertNotEqual(p.returncode, 0)
        gaps = self.report()["coverage_gaps"]
        self.assertTrue(any(g["path"].startswith(".github/workflows/") and g["level"] == "critical" for g in gaps))

    def test_pr_cannot_preseed_the_evidence_chain(self):
        self.pr({".trustdiff/latest.json": json.dumps({"overall_verdict": "PASS"}), ".trustdiff/ledger.jsonl": "{}\n"})
        p = self.gate()
        self.assertNotEqual(p.returncode, 0); self.assertIn("tracks .trustdiff", p.stdout + p.stderr)

    def test_hostile_git_config_in_the_checkout_is_refused_not_executed(self):
        self.pr({"app.py": "x = 3\n"})
        marker = self.base_dir / "PWNED-HOOK"
        hook = self.base_dir / "hook.sh"; hook.write_text(f"#!/bin/sh\ntouch {marker}\n"); hook.chmod(0o755)
        sh("git", "config", "core.fsmonitor", str(hook), cwd=self.cand)
        sh("git", "config", "diff.external", str(hook), cwd=self.cand)
        sh("git", "config", "filter.evil.clean", str(hook), cwd=self.cand)
        p = self.gate()
        self.assertNotEqual(p.returncode, 0); self.assertIn("can execute commands", p.stdout + p.stderr)
        self.assertFalse(marker.exists())

    def test_hostile_git_config_cannot_execute_via_evidence_validator_either(self):
        import trustdiff_evidence as ev
        self.pr({"app.py": "x = 4\n"})
        marker = self.base_dir / "PWNED-VALIDATOR"
        hook = self.base_dir / "hook2.sh"; hook.write_text(f"#!/bin/sh\ntouch {marker}\n"); hook.chmod(0o755)
        sh("git", "config", "core.fsmonitor", str(hook), cwd=self.cand)
        (self.cand / ".trustdiff").mkdir(); (self.cand / ".trustdiff" / "latest.json").write_text(json.dumps({"overall_verdict": "PASS", "target_commit": "a" * 40}))
        a = ev.validate(self.cand / ".trustdiff", self.cand)
        self.assertFalse(a.trusted); self.assertFalse(marker.exists())
        self.assertEqual(a.checks.get("git_config"), "unsafe")

    def test_pr_with_unpinned_image_cannot_execute_tests(self):
        self.pr({"trustdiff.contracts.json": json.dumps({"version": 2, "contracts": [{"id": "T", "type": "test", "command": ["python3", "-m", "unittest"], "covers": []}]})})
        # contracts come from the BASE; craft a base-compatible check: use the base policy but request execution with an unpinned tag
        p = self.gate("--runner", "docker", "--image", "python:3.11-slim", "--require-pinned-image")
        self.assertNotEqual(p.returncode, 0)

    def test_fork_pr_flow_reaches_a_fail_for_the_forbidden_pattern_and_produces_review_artifacts(self):
        self.pr({"app.py": "import requests\nrequests.get(url, verify=False)\n"})
        self.assertNotEqual(self.gate().returncode, 0)
        for fmt, name in (("markdown", "summary.md"), ("sarif", "findings.sarif")):
            out = self.cand / ".trustdiff" / name
            r = subprocess.run([sys.executable, str(self.verifier / "trustdiff.py"), "report", "--format", fmt, "--output", str(out)], cwd=self.cand, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr); self.assertTrue(out.exists())
        self.assertNotIn("is secure", (self.cand / ".trustdiff" / "summary.md").read_text().lower())


if __name__ == "__main__":
    unittest.main()
