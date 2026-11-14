"""P0-02: static policy for the GitHub workflows, plus a test of the policy checker itself.

This does NOT replace running the workflows on GitHub (see docs/SECURITY_MODEL.md, 'What is not covered'):
it prevents regressions in the properties that make the gate trustworthy.
"""
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

import trustdiff_supply as supply

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
INJECTABLE = re.compile(r"\$\{\{[^}]*(head_ref|\.title|\.body|head\.ref|head\.label|head\.repo|\.message|\.email|\.name|commits|author|issue\.|comment\.|review\.)[^}]*\}\}", re.I)
WRITE_ALLOWED = {"package-provenance.yml": {"id-token", "attestations"}}


def load(name_or_doc):
    if isinstance(name_or_doc, dict):
        return name_or_doc
    return yaml.safe_load((WORKFLOWS / name_or_doc).read_text())


def triggers(doc):
    on = doc.get("on", doc.get(True))
    return set(on) if isinstance(on, dict) else {on} if isinstance(on, str) else set(on or [])


def steps(doc):
    for job_name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps", []) or []:
            yield job_name, job, step


def violations(doc: dict, filename: str) -> list[str]:
    out: list[str] = []
    if "permissions" not in doc:
        out.append("top-level permissions block is missing")
    elif doc["permissions"] in ("write-all", "read-all"):
        out.append("top-level permissions must be explicit")
    for job_name, job in (doc.get("jobs") or {}).items():
        perms = job.get("permissions", {})
        if isinstance(perms, dict):
            for scope, level in perms.items():
                if level == "write" and scope not in WRITE_ALLOWED.get(filename, set()):
                    out.append(f"{job_name}: unexpected write permission {scope}")
        if "uses" in job and not (job["uses"].startswith("./") or SHA_RE.match(job["uses"])):
            out.append(f"{job_name}: reusable workflow is not pinned to a commit SHA or local path")
    for job_name, job, step in steps(doc):
        uses = step.get("uses")
        if uses and not uses.startswith("./") and not SHA_RE.match(uses):
            out.append(f"{job_name}: action not pinned to a full commit SHA: {uses}")
        if uses and uses.startswith("actions/checkout@") and (step.get("with") or {}).get("persist-credentials") is not False:
            out.append(f"{job_name}: checkout must set persist-credentials: false")
        run = step.get("run", "")
        if INJECTABLE.search(run):
            out.append(f"{job_name}: attacker-controllable expression interpolated into a shell script")
    return out


def gate_violations(verify: dict, gate: dict) -> list[str]:
    out: list[str] = []
    if triggers(gate) - {"pull_request_target"}:
        out.append("gate must be triggered only by pull_request_target (workflow loaded from the base branch)")
    if "pull_request" in triggers(verify) or "pull_request_target" in triggers(verify) or "push" in triggers(verify):
        out.append("the reusable verifier must only be workflow_call")
    jobs = verify["jobs"]
    verify_job = jobs["verify"]
    blob = json.dumps(verify_job)
    if "secrets." in blob or "environment" in verify_job:
        out.append("verify job must not have secrets or an environment")
    sign_blob = json.dumps(jobs.get("attest", {}))
    if "TRUSTDIFF_SIGNING_KEY" in json.dumps({k: v for k, v in jobs.items() if k != "attest"}):
        out.append("the signing key may be referenced only by the attest job")
    if "attest" in jobs and not jobs["attest"].get("environment"):
        out.append("attest job must be bound to a protected environment")
    # ordering inside verify: digest approval before candidate checkout before any verifier execution
    names = [s.get("name", "") for _, _, s in [(j, jb, st) for j, jb, st in steps({"jobs": {"verify": verify_job}})]]
    def idx(fragment):
        return next((i for i, n in enumerate(names) if fragment in n), None)
    if None in (idx("approved verifier digest"), idx("CANDIDATE"), idx("Verify (trusted")):
        out.append("expected verify steps are missing")
    elif not idx("approved verifier digest") < idx("CANDIDATE") < idx("Verify (trusted"):
        out.append("the verifier digest must be approved before the candidate is checked out and before verification runs")
    # the candidate is never executed on the host
    allowed = (r"^\s*test \"\$\(git -C candidate rev-parse HEAD\)\" = \"\$HEAD_SHA\"\s*$",)
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            run = step.get("run", "")
            for line in run.splitlines():
                if "candidate" in line and not any(re.match(p, line) for p in allowed) and "trusted/trustdiff.py" not in line and "cp -a .trustdiff-download" not in line:
                    if re.search(r"\b(pip|npm|yarn|make|bash|sh|source|python3?|\./)\b", line) and "$GITHUB_WORKSPACE/trusted/" not in line and ".sign-venv" not in line:
                        out.append(f"{job_name}: step may execute candidate content: {line.strip()}")
    gate_step = next((s for s in verify_job["steps"] if "Verify (trusted" in s.get("name", "")), {})
    run = gate_step.get("run", "")
    for needed in ("--require-pinned-image", "--runner docker", "$GITHUB_WORKSPACE/trusted/trustdiff.py"):
        if needed not in run:
            out.append(f"verification step must contain {needed}")
    if "docker pull python" in json.dumps(verify) or ":3." in run:
        out.append("runner image must come from the digest-pinned variable, not a mutable tag")
    return out


@unittest.skipUnless(yaml, "PyYAML required (installed in CI)")
class RealWorkflowTests(unittest.TestCase):
    def test_every_workflow_passes_the_baseline_policy(self):
        files = sorted(p.name for p in WORKFLOWS.glob("*.yml"))
        self.assertGreaterEqual(len(files), 4)
        for name in files:
            with self.subTest(name):
                self.assertEqual(violations(load(name), name), [])

    def test_gate_trust_boundaries(self):
        self.assertEqual(gate_violations(load("trustdiff-verify.yml"), load("trustdiff-gate.yml")), [])

    def test_gate_calls_the_local_reusable_workflow_with_least_privilege(self):
        gate = load("trustdiff-gate.yml")
        self.assertEqual(gate["permissions"], {})
        self.assertEqual(gate["jobs"]["gate"]["permissions"], {"contents": "read"})
        self.assertEqual(gate["jobs"]["gate"]["uses"], "./.github/workflows/trustdiff-verify.yml")

    def test_inline_digest_algorithm_matches_the_python_implementation(self):
        """The workflow computes the verifier digest with its own inline code so a compromised base cannot vouch for itself."""
        doc = load("trustdiff-verify.yml")
        for job in ("verify", "attest"):
            step = next(s for s in doc["jobs"][job]["steps"] if "approved verifier digest" in s.get("name", ""))
            script = step["run"].split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
            script = "\n".join(line[10:] if line.startswith(" " * 10) else line for line in script.splitlines())
            files = re.search(r"FILES = \((.*?)\)", script).group(1)
            self.assertEqual(tuple(re.findall(r'"([^"]+)"', files)), supply.VERIFIER_FILES, job)
            work = tempfile.mkdtemp()
            # The digest check requires real files in the trusted checkout.
            import shutil
            trusted = Path(work) / "trusted"
            trusted.mkdir()
            for filename in supply.VERIFIER_FILES:
                shutil.copyfile(ROOT / filename, trusted / filename)
            ok = subprocess.run([sys.executable, "-c", script], cwd=work, env={**os.environ, "EXPECTED": supply.verifier_digest()}, capture_output=True, text=True)
            self.assertIn("verifier digest approved", ok.stdout, ok.stderr)
            bad = subprocess.run([sys.executable, "-c", script], cwd=work, env={**os.environ, "EXPECTED": "0" * 64}, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            empty = subprocess.run([sys.executable, "-c", script], cwd=work, env={**os.environ, "EXPECTED": ""}, capture_output=True, text=True)
            self.assertNotEqual(empty.returncode, 0); self.assertIn("not set", empty.stderr)

    def test_dependabot_waits_before_adopting_new_action_releases(self):
        cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
        update = cfg["updates"][0]
        self.assertEqual(update["package-ecosystem"], "github-actions"); self.assertGreaterEqual(update["cooldown"]["default-days"], 3)

    def test_ci_runs_real_docker_tests(self):
        ci = load("ci.yml")
        self.assertIn("docker-integration", ci["jobs"])
        self.assertIn("test_runner_hardening", json.dumps(ci["jobs"]["docker-integration"]))


@unittest.skipUnless(yaml, "PyYAML required (installed in CI)")
class PolicyCheckerSelfTests(unittest.TestCase):
    """The checker must actually catch each class of mistake, otherwise passing it means nothing."""

    def base(self):
        return copy.deepcopy(load("trustdiff-verify.yml")), copy.deepcopy(load("trustdiff-gate.yml"))

    def test_unpinned_action_is_flagged(self):
        v, _ = self.base(); v["jobs"]["verify"]["steps"][0]["uses"] = "actions/checkout@v4"
        self.assertTrue(any("not pinned" in x for x in violations(v, "x.yml")))

    def test_short_sha_is_flagged(self):
        v, _ = self.base(); v["jobs"]["verify"]["steps"][0]["uses"] = "actions/checkout@11bd719"
        self.assertTrue(violations(v, "x.yml"))

    def test_persisted_credentials_are_flagged(self):
        v, _ = self.base(); v["jobs"]["verify"]["steps"][0]["with"]["persist-credentials"] = True
        self.assertTrue(any("persist-credentials" in x for x in violations(v, "x.yml")))

    def test_write_permissions_and_missing_permissions_are_flagged(self):
        v, _ = self.base(); v["jobs"]["verify"]["permissions"]["contents"] = "write"
        self.assertTrue(any("write permission" in x for x in violations(v, "x.yml")))
        del v["permissions"]; self.assertTrue(any("permissions block" in x for x in violations(v, "x.yml")))

    def test_expression_injection_is_flagged(self):
        v, _ = self.base(); v["jobs"]["verify"]["steps"][1]["run"] = 'echo "${{ github.event.pull_request.title }}"'
        self.assertTrue(any("attacker-controllable" in x for x in violations(v, "x.yml")))
        v["jobs"]["verify"]["steps"][1]["run"] = 'echo "${{ github.head_ref }}"'
        self.assertTrue(any("attacker-controllable" in x for x in violations(v, "x.yml")))

    def test_plain_pull_request_trigger_for_the_gate_is_flagged(self):
        v, g = self.base(); g["on"] = {"pull_request": None}
        self.assertTrue(any("pull_request_target" in x for x in gate_violations(v, g)))

    def test_secret_in_the_verify_job_is_flagged(self):
        v, g = self.base(); v["jobs"]["verify"]["steps"][1]["env"]["K"] = "${{ secrets.TRUSTDIFF_SIGNING_KEY }}"
        self.assertTrue(gate_violations(v, g))

    def test_signing_without_protected_environment_is_flagged(self):
        v, g = self.base(); del v["jobs"]["attest"]["environment"]
        self.assertTrue(any("protected environment" in x for x in gate_violations(v, g)))

    def test_executing_the_candidate_on_the_host_is_flagged(self):
        v, g = self.base(); v["jobs"]["verify"]["steps"].insert(4, {"name": "oops", "run": "cd candidate && pip install ."})
        self.assertTrue(any("execute candidate" in x for x in gate_violations(v, g)))
        v, g = self.base(); v["jobs"]["verify"]["steps"].insert(4, {"name": "oops", "run": "bash candidate/build.sh"})
        self.assertTrue(any("execute candidate" in x for x in gate_violations(v, g)))

    def test_reordering_digest_check_after_candidate_checkout_is_flagged(self):
        v, g = self.base(); st = v["jobs"]["verify"]["steps"]; st[1], st[2] = st[2], st[1]
        self.assertTrue(any("before the candidate" in x for x in gate_violations(v, g)))

    def test_mutable_runner_image_tag_is_flagged(self):
        v, g = self.base(); v["jobs"]["verify"]["steps"][5]["run"] += "\ndocker pull python:3.11-slim"
        self.assertTrue(any("mutable tag" in x for x in gate_violations(v, g)))

    def test_dropping_pinned_image_enforcement_is_flagged(self):
        v, g = self.base()
        step = next(s for s in v["jobs"]["verify"]["steps"] if "Verify (trusted" in s.get("name", ""))
        step["run"] = step["run"].replace("--require-pinned-image", "")
        self.assertTrue(any("--require-pinned-image" in x for x in gate_violations(v, g)))


if __name__ == "__main__":
    unittest.main()
