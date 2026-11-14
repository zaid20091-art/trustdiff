import argparse
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import trustdiff
import trustdiff_challenge as challenge
import trustdiff_evidence as evidence
import trustdiff_repair as repair
import trustdiff_runner as runner
import trustdiff_safe as safe
import trustdiff_supply as supply
from test_evidence_validator import Env, HAVE_CRYPTO, CLI, sh, commit


class ReleaseFeatures(Env):
    def test_independent_check_rejects_wrong_pin_and_accepts_protected_state(self):
        args = ["check", "--baseline", self.base_commit, "--verifier-sha256"]
        wrong = sh(*CLI, *args, "0" * 64, cwd=self.repo, check=False)
        self.assertEqual(wrong.returncode, 2)
        self.assertIn("approved SHA-256", wrong.stderr)
        digest = supply.verifier_digest()
        internal = sh(*CLI, *args, digest, cwd=self.repo, check=False)
        self.assertEqual(internal.returncode, 2)
        self.assertIn("outside the candidate", internal.stderr)
        with mock.patch.object(trustdiff, "ROOT", self.repo), mock.patch.object(trustdiff, "STATE", self.outside / "checked"):
            self.assertEqual(trustdiff.check_cmd(trustdiff.parser().parse_args([*args, digest]), quiet=True), 0)

    def test_lfs_uses_only_verified_local_content(self):
        binary = b"fixture\x00bytes\xff"
        digest = hashlib.sha256(binary).hexdigest()
        if not shutil.which("git-lfs"):
            self.skipTest("Git LFS executable unavailable")
        sh("git", "lfs", "install", "--local", "--skip-smudge", cwd=self.repo)
        (self.repo / ".gitattributes").write_text("asset.bin filter=lfs diff=lfs merge=lfs -text\n")
        pointer = subprocess.run(["git", "lfs", "clean", "--", "asset.bin"], input=binary, cwd=self.repo,
                                 capture_output=True, check=True).stdout
        (self.repo / "asset.bin").write_bytes(pointer)
        sh("git", "-c", "filter.lfs.process=", "-c", "filter.lfs.clean=", "-c", "filter.lfs.required=false",
           "add", "-A", cwd=self.repo)
        sh("git", "-c", "core.hooksPath=" + str(self.outside), "-c", "filter.lfs.process=", "-c", "filter.lfs.clean=",
           "-c", "filter.lfs.required=false", "-c", "user.name=T", "-c", "user.email=t@example.invalid",
           "commit", "-qm", "lfs object", cwd=self.repo)
        head = sh("git", "rev-parse", "HEAD", cwd=self.repo).stdout.strip()
        (self.repo / "asset.bin").write_bytes(binary)
        self.assertEqual(safe.git_config_risks(self.repo), [])
        self.assertTrue(runner.clean_candidate(self.repo, self.state))
        with self.assertRaisesRegex(ValueError, "LFS content required"):
            runner.export_snapshot(self.repo, head, self.outside / "missing")
        cache = self.outside / "approved-lfs"
        source = cache / digest[:2] / digest[2:4] / digest
        source.parent.mkdir(parents=True)
        shutil.copyfile(self.repo / ".git/lfs/objects" / digest[:2] / digest[2:4] / digest, source)
        runner.export_snapshot(self.repo, head, self.outside / "hydrated", cache)
        self.assertEqual((self.outside / "hydrated/asset.bin").read_bytes(), binary)
        source.write_bytes(binary[:-1] + b"!")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            runner.export_snapshot(self.repo, head, self.outside / "corrupt", cache)
        (self.repo / "asset.bin").write_bytes(binary[:-1] + b"!")
        self.assertFalse(runner.clean_candidate(self.repo, self.state))

    def test_snapshot_bypasses_hostile_smudge_commands_even_when_called_directly(self):
        (self.repo / ".gitattributes").write_text("app.py filter=lfs\n")
        sh("git", "-c", "filter.lfs.process=", "-c", "filter.lfs.clean=", "-c", "filter.lfs.required=false",
           "add", "-A", cwd=self.repo)
        sh("git", "-c", "filter.lfs.process=", "-c", "filter.lfs.clean=", "-c", "filter.lfs.required=false",
           "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "attributes", cwd=self.repo)
        head = sh("git", "rev-parse", "HEAD", cwd=self.repo).stdout.strip()
        sh("git", "config", "filter.lfs.process", "fatal-command-with-spaces", cwd=self.repo)
        sh("git", "config", "filter.lfs.smudge", "fatal-command-with-spaces", cwd=self.repo)
        self.assertTrue(safe.git_config_risks(self.repo))
        runner.export_snapshot(self.repo, head, self.outside / "export")
        self.assertEqual((self.outside / "export/app.py").read_bytes(), b"x = 2\n")

    def test_four_domains_validate_expected_values_and_baseline(self):
        cases = [
            ("authorization", ['user'], [False], "return role == 'admin'", "return True", "role"),
            ("money", ["invoice", "invoice"], [True, False], "return key not in seen and not seen.add(key)", "return True", "key"),
            ("database", [1], [{"rows": [1]}], "return {'rows': [version]}", "return {'rows': []}", "version"),
            ("api", ["v1"], [{"status": 200}], "return {'status': 200}", "return {'status': 404}", "version"),
        ]
        for domain, args, expected, good, bad, argument in cases:
            with self.subTest(domain=domain):
                case = {"path": "behavior.py", "domain": domain, "expected": expected,
                        "calls": [{"function": "evaluate", "args": [value]} for value in args]}
                (self.repo / "behavior.py").write_text(f"seen = set()\ndef evaluate({argument}):\n    {good}\n")
                baseline = commit(self.repo, "expected")
                (self.repo / "behavior.py").write_text(f"def evaluate({argument}):\n    {bad}\n")
                target = commit(self.repo, "regression")
                actual = challenge.evaluate(case, self.repo, baseline, target, "host", "", 5)
                self.assertEqual(actual[0], "FAIL", actual)
                wrong = {**case, "expected": [None] * len(expected)}
                self.assertEqual(challenge.evaluate(wrong, self.repo, baseline, target, "host", "", 5)[0], "UNKNOWN")

    @unittest.skipUnless(HAVE_CRYPTO, "Ed25519 support unavailable")
    def test_authenticated_failure_requires_explicit_merge_success(self):
        (self.repo / "app.py").write_text("verify = False\n")
        self.head = commit(self.repo, "regression")
        check = sh(*CLI, "check", "--baseline", self.base_commit, "--repository", "owner/project", cwd=self.repo, check=False)
        self.assertEqual(check.returncode, 1, check.stderr)
        key, store = self.keys()
        result = sh(*CLI, "attest", "--key", str(key), "--principal", "ci", "--include-failure", cwd=self.repo, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.validate(store).status, evidence.VERIFIED)
        verify = [*CLI, "verify-proof", "--bundle", str(self.state / "proof.json"), "--allowed-signers", str(store),
                  "--principal", "ci", "--expected-commit", self.head, "--require-v2"]
        self.assertEqual(json.loads(sh(*verify, "--authenticate-failure", cwd=self.repo).stdout)["authenticated_verdict"], "FAIL")
        spec = importlib.util.spec_from_file_location("checks_adapter", Path(__file__).resolve().parents[1] / "integrations/github/publish_check.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = json.loads((self.state / "latest.json").read_text(encoding="utf-8"))
        args = argparse.Namespace(repository="owner/project", commit=self.head, baseline=self.base_commit,
                                  policy=report["policy_sha256"], verifier=supply.verifier_digest(),
                                  bundle=self.state / "proof.json", signers=store, principal="ci")
        with mock.patch.object(module, "urllib") as network:
            response = io.BytesIO(b'{"id": 42}')
            response.status = 201
            endpoint = mock.Mock(return_value=response)
            network.request.Request.side_effect = __import__("urllib.request").request.Request
            self.assertEqual(module.publish(args, "test-token", endpoint=endpoint), 42)
            sent = json.loads(endpoint.call_args.args[0].data)
            self.assertEqual((sent["head_sha"], sent["conclusion"]), (self.head, "failure"))
            args.repository = "other/project"
            with self.assertRaisesRegex(ValueError, "requested GitHub repository"):
                module.publish(args, "test-token", endpoint=endpoint)
        self.assertEqual(sh(*verify, "--require-pass", cwd=self.repo, check=False).returncode, 1)
        self.assertEqual(sh(*verify, cwd=self.repo, check=False).returncode, 1)
        with mock.patch.object(evidence, "_worktree_dirty", return_value=None):
            self.assertFalse(self.validate(store).trusted)

    def test_repair_replays_original_and_runs_the_full_gate(self):
        case = {"id": "API-001", "type": "counterexample", "domain": "api", "path": "behavior.py",
                "calls": [{"function": "status"}], "expected": [200]}
        policy = json.dumps({"contracts": [case]})
        (self.repo / "trustdiff.contracts.json").write_text(policy)
        path = self.repo / "behavior.py"
        path.write_text("def status(): return 200\n")
        baseline = commit(self.repo, "approved oracle")
        path.write_text("def status(): return 404\n")
        original = commit(self.repo, "bad")
        path.write_text("def status(): return 200\n")
        repaired = commit(self.repo, "repair")
        args = trustdiff.parser().parse_args(["reproduce", "--case", case["id"], "--baseline", baseline,
                                             "--target", original, "--repair", repaired, "--image", "python@sha256:" + "1" * 64,
                                             "--policy-sha256", hashlib.sha256(policy.encode()).hexdigest(),
                                             "--verifier-sha256", supply.verifier_digest()])
        real = challenge.execute_script

        def use_fixture_host(root, revision, script, mode, image, timeout, runtime, lfs_cache):
            return real(root, revision, script, "host", image, timeout, runtime, lfs_cache)

        with mock.patch.object(trustdiff, "ROOT", self.repo), mock.patch.object(trustdiff, "STATE", self.outside / "evidence"), \
                mock.patch.object(challenge, "execute_script", side_effect=use_fixture_host) as runs, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(repair.reproduce(args), 0)
            result = json.loads(output.getvalue())
        self.assertEqual((result["original"]["verdict"], result["repair"]["verdict"], result["gate_exit"]), ("FAIL", "PASS", 0))
        self.assertEqual(runs.call_count, 6)


if __name__ == "__main__":
    unittest.main()
