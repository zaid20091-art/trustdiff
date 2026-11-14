"""P0-05: untrusted-input hardening. Regression tests for every issue reproduced in review, plus seeded fuzzing and
property tests (stdlib only, deterministic seeds; an optional Hypothesis class runs when the package is installed).

Properties asserted throughout: no unhandled exception, bounded time and memory, and FAIL CLOSED - a hostile input
may produce ERROR/INVALID_EVIDENCE but never a PASS or a VERIFIED verdict.
"""
import copy
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from support import symlink_or_skip

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_evidence_validator import CLI, CONTRACTS, HAVE_CRYPTO, Env, commit, sh  # noqa: E402

import trustdiff
import trustdiff_challenge
import trustdiff_evidence as ev
import trustdiff_impact
import trustdiff_proof as proof
import trustdiff_safe as safe

ROOT = Path(__file__).resolve().parents[1]


def run_isolated(code: str, timeout: float = 25, cwd=None):
    """Run python code in a child so a regression (hang / blow-up) fails the test instead of freezing the suite."""
    return subprocess.run([sys.executable, "-c", code], cwd=cwd or ROOT, capture_output=True, text=True, timeout=timeout, env={**os.environ, "PYTHONPATH": str(ROOT)})


def make_repo(files: dict[str, str | bytes], contracts=CONTRACTS):
    d = Path(tempfile.mkdtemp()).resolve()
    sh("git", "init", "-q", "-b", "main", cwd=d)
    (d / "trustdiff.contracts.json").write_text(contracts if isinstance(contracts, str) else json.dumps(contracts))
    (d / "app.py").write_text("x = 1\n")
    base = commit(d, "base")
    for rel, content in files.items():
        path = d / rel; path.parent.mkdir(parents=True, exist_ok=True)
        (path.write_bytes if isinstance(content, bytes) else path.write_text)(content)
    return d, base, commit(d, "change")


def cli(repo, *args):
    return subprocess.run(CLI + list(args), cwd=repo, text=True, capture_output=True, timeout=120)


class ReproducedIssueRegressions(unittest.TestCase):
    def test_js_import_scanner_has_no_quadratic_backtracking(self):
        for name, content in {
            "spaces after from": "import x from" + " " * 300_000,
            "many unterminated": "from '.a" * 100_000,
            "import paren spaces": "import" + " " * 300_000 + "(",
            "quote soup": "require(" + "'./" * 100_000,
            "newline run": "from\n" * 200_000,
        }.items():
            with self.subTest(name):
                t = time.time()
                r = subprocess.run(
                    [sys.executable, "-c", "import sys, trustdiff_impact as i\ni._javascript_imports('a.js', sys.stdin.read(), {'a.js'})"],
                    input=content, text=True, capture_output=True, timeout=15, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)})
                self.assertEqual(r.returncode, 0, r.stderr); self.assertLess(time.time() - t, 5)

    def test_js_import_scanner_still_finds_real_imports(self):
        found = trustdiff_impact._javascript_imports("src/a.ts", "import { x } from './b'\nconst c = require('../lib/c')\nimport('./d')", {"src/b.ts", "lib/c.js", "src/d.js"})
        self.assertEqual(found, {"src/b.ts", "lib/c.js", "src/d.js"})

    def test_hostile_python_sources_degrade_instead_of_crashing(self):
        for name, source in {"deep expression": "x = " + "1+" * 60000 + "1\n", "nul byte": "x = 1\0\n", "huge nesting": "(" * 5000 + ")" * 5000, "deep attribute": "a" + ".b" * 50000}.items():
            with self.subTest(name):
                status = []
                self.assertEqual(trustdiff_impact._python_imports("m.py", source, {"m.py"}, status), set())
        d, base, head = make_repo({"deep.py": "x = " + "1+" * 60000 + "1\n", "ok.py": "import app\n"})
        graph = trustdiff_impact.impact_graph(d, [{"status": "M", "path": "app.py"}])
        self.assertTrue(graph["incomplete"]); self.assertGreaterEqual(graph["skipped_files"], 1)
        self.assertIn("ok.py", graph["affected_files"])             # analysis of OTHER files continues

    def test_challenge_discovery_survives_hostile_source(self):
        d, base, head = make_repo({"auth.py": "x = " + "1+" * 60000 + "1\n"})
        self.assertEqual(trustdiff_challenge.discover(d, [{"status": "A", "path": "auth.py"}]), [])

    def test_unusual_file_names_are_reported_exactly(self):
        names = {"café_auth.py": "def can_access_admin(role):\n    return True\n", "a b/harmless.py": "def f(role):\n    return role == 'admin'\n",
                 "日本語/権限.py": "v = 5\n"}
        if os.name != "nt":
            names.update({'q"uote.py': "y = 2\n", "tab\tname.py": "z = 3\n", "new\nline.py": "w = 4\n"})
        d, base, head = make_repo(names)
        os.environ["TD_TEST_ROOT"] = str(d)
        code = f"""
import json, os, sys
os.chdir({str(d)!r}); sys.path.insert(0, {str(ROOT)!r})
import trustdiff
print(json.dumps(sorted(f['path'] for f in trustdiff.changed_files({base!r}, {head!r}))))
"""
        out = json.loads(run_isolated(code).stdout)
        self.assertEqual(out, sorted(names))                                           # exact, no quoting artefacts

    def test_patch_content_is_attributed_to_the_right_file_even_with_deceptive_names(self):
        d, base, head = make_repo({"a b/harmless.py": "def f(role):\n    return role == 'admin'\n"})
        risks = trustdiff_impact.risk_from_patch(d, base, head, [{"status": "A", "path": "a b/harmless.py"}])
        self.assertIn(("a b/harmless.py", "authorization"), {(r["path"], r["topic"]) for r in risks})

    def test_unicode_named_admin_function_is_no_longer_skipped_by_challenge_discovery(self):
        d, base, head = make_repo({"café_auth.py": "def can_access_admin(role):\n    return True\n"})
        out = run_isolated(f"""
import os, sys, json
os.chdir({str(d)!r}); sys.path.insert(0, {str(ROOT)!r})
import trustdiff, trustdiff_challenge
files = trustdiff.changed_files({base!r}, {head!r})
print(json.dumps([c['path'] for c in trustdiff_challenge.discover(trustdiff.ROOT, files)]))""").stdout
        self.assertEqual(json.loads(out), ["café_auth.py"])

    @unittest.skipIf(os.name == "nt", "Windows does not support newline in a filename")
    def test_check_reports_unusual_paths(self):
        d, base, head = make_repo({"new\nline.py": "w = 4\n", "ok.py": "q = 1\n"})
        self.assertEqual(cli(d, "check", "--baseline", base).returncode, 0)
        report = json.loads((d / ".trustdiff" / "latest.json").read_text())
        self.assertEqual(report["unusual_paths"], ["new\nline.py"])

    def test_chatty_command_cannot_exhaust_verifier_memory(self):
        code = """
import sys
import trustdiff
rc, out, err = trustdiff.run([sys.executable, '-c', "import sys\\nfor _ in range(400): sys.stdout.write('A'*1000000)"], timeout=60)
if sys.platform == 'win32':
    import ctypes
    counters = (ctypes.c_size_t * 10)()
    counters[0] = ctypes.sizeof(counters)
    if not ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(-1), ctypes.byref(counters), ctypes.sizeof(counters)):
        raise OSError('cannot read peak working set')
    peak = counters[1 if ctypes.sizeof(ctypes.c_size_t) == 8 else 2]
else:
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == 'darwin' else 1024)
print(rc, len(out), peak)"""
        rc, length, peak = map(int, run_isolated(code, timeout=60).stdout.split())
        self.assertEqual(rc, safe.RC_OVERFLOW); self.assertLessEqual(length, 1024 * 1024); self.assertLess(peak, 200_000 * 1024)

    def test_tracked_symlink_to_a_host_file_is_not_followed(self):
        d = Path(tempfile.mkdtemp()).resolve(); sh("git", "init", "-q", "-b", "main", cwd=d)
        (d / "trustdiff.contracts.json").write_text(json.dumps(CONTRACTS)); (d / "app.py").write_text("x=1\n"); base = commit(d, "b")
        secret = d.with_name(d.name + "-outside-secret.txt")
        secret.write_text("outside-marker-data")
        self.addCleanup(secret.unlink)
        symlink_or_skip(self, secret, d / "leak.py"); head = commit(d, "link")
        graph = trustdiff_impact.impact_graph(d, [{"status": "A", "path": "leak.py"}])
        self.assertGreaterEqual(graph["skipped_files"], 1)
        self.assertEqual(trustdiff_challenge.discover(d, [{"status": "A", "path": "leak.py"}]), [])
        self.assertEqual(cli(d, "check", "--baseline", base).returncode, 0)
        self.assertNotIn("outside-marker-data", (d / ".trustdiff" / "latest.json").read_text())

    def test_oversized_regular_file_is_not_slurped(self):
        big = Path(tempfile.mkdtemp()) / "big"; big.write_bytes(b"A" * (safe.MAX_SOURCE_FILE + 1))
        self.assertIsNone(safe.read_regular_text(big))
        self.assertEqual(safe.regular_file_sha256(big, limit=10)[1], "too-large")


class HostileContractAndClaimInputs(unittest.TestCase):
    def check_contracts(self, contracts, expect_ok=False):
        d, base, head = make_repo({"app.py": "x = 2\n"}, contracts=contracts)
        p = cli(d, "check", "--baseline", base)
        self.assertNotIn("Traceback", p.stderr + p.stdout)
        return p

    def test_invalid_contract_fields_are_rejected_cleanly(self):
        bad = {
            "string timeout": [{"id": "A", "type": "test", "command": ["true"], "timeout_seconds": "abc"}],
            "huge timeout": [{"id": "A", "type": "test", "command": ["true"], "timeout_seconds": 10 ** 9}],
            "negative timeout": [{"id": "A", "type": "test", "command": ["true"], "timeout_seconds": -5}],
            "bool timeout": [{"id": "A", "type": "test", "command": ["true"], "timeout_seconds": True}],
            "control id": [{"id": "A\x1b[2J", "type": "policy"}],
            "duplicate ids": [{"id": "A", "type": "policy"}, {"id": "A", "type": "policy"}],
            "command not list": [{"id": "A", "type": "test", "command": "rm -rf /"}],
            "giant command": [{"id": "A", "type": "test", "command": ["x"] * 1000}],
            "covers not list": [{"id": "A", "type": "policy", "covers": "authorization"}],
            "required string": [{"id": "A", "type": "policy", "required": "no"}],
            "not objects": ["A", 1, None],
            "too many": [{"id": f"C{i}", "type": "policy"} for i in range(600)],
        }
        for name, contracts in bad.items():
            with self.subTest(name):
                p = self.check_contracts({"version": 2, "contracts": contracts})
                self.assertNotEqual(p.returncode, 0)

    def test_deeply_nested_or_oversized_policy_file_is_rejected_cleanly(self):
        for name, text in {"deep": "[" * 200_000 + "]" * 200_000, "huge": json.dumps({"contracts": [], "pad": "a" * 1_200_000}), "not json": "{{{"}.items():
            with self.subTest(name):
                p = self.check_contracts(text)
                self.assertNotEqual(p.returncode, 0)

    def test_catastrophic_regex_in_a_contract_yields_error_not_a_hang_or_pass(self):
        contracts = {"version": 2, "contracts": [{"id": "RE", "type": "deny_pattern", "pattern": "(a+)+$", "covers": []}]}
        d, base, head = make_repo({"app.py": "x = '" + "a" * 45 + "!'\n"}, contracts=contracts)
        t = time.time(); p = cli(d, "check", "--baseline", base)
        report = json.loads((d / ".trustdiff" / "latest.json").read_text())
        verdict = report["results"][0]
        self.assertEqual(verdict["verdict"], "ERROR"); self.assertIn("catastrophic", verdict["explanation"])
        self.assertNotEqual(p.returncode, 0); self.assertLess(time.time() - t, 40)

    def test_invalid_regex_is_error_and_normal_regex_still_works(self):
        hits, err = safe.regex_hits("(", ["x"]); self.assertIsNone(hits); self.assertIn("invalid", err)
        self.assertEqual(safe.regex_hits("verify\\s*=\\s*False", ["a", "verify = False"]), (["verify = False"], None))
        self.assertEqual(safe.regex_hits("zzz", ["a", "b"]), ([], None))
        hits, err = safe.regex_hits("(a+)+$", ["a" * 45 + "!"], timeout=1.5); self.assertIsNone(hits); self.assertIn("catastrophic", err)

    def test_diff_larger_than_the_limit_is_an_error_never_a_silent_pass(self):
        d, base, head = make_repo({"big.txt": ("line of filler text for the diff\n" * 600_000)})     # ~20 MB added
        p = cli(d, "check", "--baseline", base)
        report = json.loads((d / ".trustdiff" / "latest.json").read_text())
        deny = next(r for r in report["results"] if r["contract_id"] == "DENY-TLS")
        self.assertEqual(deny["verdict"], "ERROR"); self.assertNotEqual(p.returncode, 0)

    def test_hostile_claims_file_is_rejected_cleanly(self):
        d, base, head = make_repo({"app.py": "x = 2\n"})
        for name, content in {"array": "[]", "claims string": '{"claims": "x"}', "claim not object": '{"claims": [1]}', "requirements string": '{"claims": [{"requirements": "A"}]}', "deep": "[" * 100000}.items():
            with self.subTest(name):
                (d / "claims.json").write_text(content)
                p = cli(d, "check", "--baseline", base, "--claims", "claims.json")
                self.assertNotIn("Traceback", p.stderr); self.assertNotEqual(p.returncode, 0)

    def test_report_rendering_survives_hostile_reports(self):
        d = Path(tempfile.mkdtemp())
        hostile = [
            {"results": "oops", "claims": [1, 2], "coverage_gaps": [{"level": None}], "limitations": "x"},
            {"results": [{"contract_id": None}, 5], "coverage_gaps": [{"path": {"a": 1}}], "semantic_hypotheses": [None], "test_weakening": [{"message": ["x"]}]},
            {"overall_verdict": {"x": 1}, "results": [{"contract_id": "<script>alert(1)</script>", "verdict": "PASS", "explanation": "@everyone [x](javascript:alert(1))"}]},
        ]
        for i, report in enumerate(hostile):
            (d / "r.json").write_text(json.dumps(report))
            for fmt in ("json", "markdown", "html", "sarif"):
                with self.subTest(i=i, fmt=fmt):
                    p = cli(d, "report", "--input", str(d / "r.json"), "--format", fmt, "--output", str(d / f"out.{fmt}"))
                    self.assertEqual(p.returncode, 0, p.stderr)
        text = (d / "out.html").read_text(); self.assertNotIn("<script>alert", text)
        self.assertNotIn("@everyone", (d / "out.markdown").read_text().replace("@\u200b", ""))   # mentions are neutralised

    def test_non_object_report_is_rejected_cleanly(self):
        d = Path(tempfile.mkdtemp()); (d / "r.json").write_text("[1,2,3]")
        p = cli(d, "report", "--input", str(d / "r.json"), "--format", "markdown")
        self.assertNotEqual(p.returncode, 0); self.assertNotIn("Traceback", p.stderr + p.stdout)


class FuzzTests(unittest.TestCase):
    ATOMS = [None, True, False, 0, 1, -1, 2 ** 70, 1.5, "", "a", "A" * 500, "\x00", "\u202e", "../x", [], {}, [[]], {"a": {"b": {}}}]

    def rand_json(self, rng, depth=0):
        r = rng.random()
        if depth > 3 or r < 0.45: return rng.choice(self.ATOMS)
        if r < 0.7: return [self.rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
        return {rng.choice(["id", "type", "covers", "command", "timeout_seconds", "pattern", "required", "match", "x"]): self.rand_json(rng, depth + 1) for _ in range(rng.randint(0, 5))}

    def test_validate_contracts_only_ever_raises_value_error(self):
        rng = random.Random(1337)
        valid = {"id": "C1", "type": "test", "command": ["python3", "-m", "unittest"], "covers": ["authorization"], "required": True, "timeout_seconds": 30}
        accepted = 0
        for _ in range(4000):
            contract = copy.deepcopy(valid)
            for _ in range(rng.randint(0, 3)):
                key = rng.choice(list(valid) + ["extra"]); contract[key] = self.rand_json(rng)
            candidate = rng.choice([[contract], contract, [contract, contract], self.rand_json(rng)])
            try:
                trustdiff.validate_contracts(candidate)
                accepted += 1
                for c in candidate:                                                # property: accepted input satisfies the schema
                    self.assertIsInstance(c["id"], str); self.assertLessEqual(len(c["id"]), 200)
                    self.assertTrue(1 <= c.get("timeout_seconds", 30) <= 600)
                    self.assertLessEqual(len(c.get("command", ["x"])), 64)
            except ValueError:
                pass
        self.assertGreater(accepted, 0)

    def test_untrusted_text_sanitisers_respect_their_bounds(self):
        rng = random.Random(7)
        for _ in range(2000):
            value = rng.choice(["".join(rng.choice(string.printable + "\u202e\u2028\x00\x1b") for _ in range(rng.randint(0, 800))), self.rand_json(rng)])
            self.assertLessEqual(len(ev.clip(value)), ev.MAX_STRING)
            self.assertNotRegex(ev.clip(value), r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e]")
            item = ev.scalar_dict(self.rand_json(rng))
            self.assertTrue(all(isinstance(v, (str, int, float, bool, list, type(None))) for v in item.values()))
            self.assertLessEqual(len(ev.scalar_list([self.rand_json(rng) for _ in range(300)])), ev.MAX_ITEMS)

    def test_name_status_parser_never_raises_and_round_trips(self):
        rng = random.Random(11)
        for _ in range(3000):
            blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 60)))
            self.assertIsInstance(safe.parse_name_status_z(blob), list)
        alphabet = ["a", " ", "b/", "é", "日", '"', "\t", "\n", "\\", "..", "."]
        for _ in range(1000):
            name = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 12))) or "x"
            parsed = safe.parse_name_status_z(b"M\0" + os.fsencode(name) + b"\0")
            self.assertEqual(parsed, [{"status": "M", "path": name}])

    def test_clean_repo_path_rejects_traversal_and_control_characters(self):
        for bad in ("", "/etc/passwd", "../x", "a/../b", "a//b", "a/./b", "a\\b", "a\nb", "a\x00b", "x" * 5000, "."):
            self.assertFalse(safe.clean_repo_path(bad), repr(bad))
        for good in ("a.py", "a b/c.py", "café/é.py", "日本語.py"):
            self.assertTrue(safe.clean_repo_path(good), good)

    def test_js_scanner_is_fast_on_random_adversarial_text(self):
        rng = random.Random(99)
        tokens = ["from", "import", "require", "(", ")", "'", '"', ".", "./", "../", " ", "\n", "x", "a/b", "\t"]
        start = time.time()
        for _ in range(300):
            text = "".join(rng.choice(tokens) for _ in range(rng.randint(0, 3000)))
            trustdiff_impact._javascript_imports("m.js", text, {"m.js", "a/b.js"})
        self.assertLess(time.time() - start, 20)

    def test_regex_worker_always_returns_a_decision(self):
        rng = random.Random(5)
        for _ in range(60):
            pattern = "".join(rng.choice(["a", "b", "(", ")", "+", "*", "?", "|", "[", "]", "\\", "^", "$", "."]) for _ in range(rng.randint(1, 12)))
            hits, error = safe.regex_hits(pattern, ["ab", "aab", ""], timeout=3)
            self.assertTrue((hits is None) != (error is None))

    def test_evidence_validator_never_raises_and_never_verifies_random_reports(self):
        d, base, head = make_repo({"app.py": "x = 2\n"})
        state = d / ".trustdiff"; state.mkdir()
        rng = random.Random(2024)
        seed = {"overall_verdict": "PASS", "integrity_verdict": "PASS", "target_commit": head, "results": [{"contract_id": "C", "verdict": "PASS"}], "evidence": [], "coverage_gaps": [], "claims": [], "input_snapshot": {}}
        for i in range(120):
            report = copy.deepcopy(seed)
            for _ in range(rng.randint(1, 4)):
                key = rng.choice(list(seed) + ["extra", "status", "limitations"])
                report[key] = self.rand_json(rng) if rng.random() < 0.8 else report.pop(key, None)
            text = json.dumps(report) if rng.random() < 0.9 else json.dumps(report)[: rng.randint(0, 60)]
            (state / "latest.json").write_text(text)
            a = ev.validate(state, d)
            self.assertIn(a.status, {ev.UNVERIFIED, ev.INVALID_EVIDENCE, ev.STALE_REPORT, ev.NOT_RUN})
            view = ev.verdict_view(a)
            self.assertFalse(view["trusted"]); self.assertIsNone(view["verdict"])
            self.assertNotEqual(view["overall_verdict"], "PASS")
            for key in ("coverage_gaps", "challenges"):
                self.assertLessEqual(len(ev.items_view(a, key)["items"]), ev.MAX_ITEMS)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography extra required")
class ProofBundleProperties(Env):
    def leaves(self, node, path=()):
        if isinstance(node, dict):
            for k, v in node.items(): yield from self.leaves(v, path + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node): yield from self.leaves(v, path + (i,))
        else:
            yield path, node

    def mutate(self, bundle, path, value):
        mutated = copy.deepcopy(bundle); cur = mutated
        for p in path[:-1]: cur = cur[p]
        if isinstance(value, bool): new = not value
        elif isinstance(value, (int, float)): new = value + 1
        elif isinstance(value, str): new = value + "x" if value else "x"
        else: new = "x"
        cur[path[-1]] = new
        return mutated

    def test_every_single_leaf_mutation_of_a_signed_bundle_is_rejected(self):
        self.check(); private, trust = self.keys()
        sh(*CLI, "attest", "--key", str(private), "--principal", "ci", cwd=self.repo)
        bundle = json.loads((self.state / "proof.json").read_text())
        self.assertEqual(proof.bundle_errors(bundle, trust, "ci", self.head), [])
        count = 0
        for path, value in self.leaves(bundle):
            count += 1
            with self.subTest(path="/".join(map(str, path))):
                self.assertTrue(proof.bundle_errors(self.mutate(bundle, path, value), trust, "ci", self.head), "mutation went undetected")
        self.assertGreater(count, 50)

    def test_dropping_any_top_level_or_nested_key_is_rejected(self):
        self.check(); private, trust = self.keys()
        sh(*CLI, "attest", "--key", str(private), "--principal", "ci", cwd=self.repo)
        bundle = json.loads((self.state / "proof.json").read_text())
        for key in list(bundle):
            broken = copy.deepcopy(bundle); del broken[key]
            with self.subTest(key=key): self.assertTrue(proof.bundle_errors(broken, trust, "ci", self.head))
        for key in list(bundle["attestation"]):
            broken = copy.deepcopy(bundle); del broken["attestation"][key]
            with self.subTest(attestation=key): self.assertTrue(proof.bundle_errors(broken, trust, "ci", self.head))

    def test_random_garbage_bundles_never_raise_and_never_verify(self):
        self.check(); private, trust = self.keys()
        sh(*CLI, "attest", "--key", str(private), "--principal", "ci", cwd=self.repo)
        good = json.loads((self.state / "proof.json").read_text())
        rng = random.Random(31337); fuzz = FuzzTests()
        for _ in range(400):
            bundle = copy.deepcopy(good)
            changed = False
            targets = [bundle, bundle["report"], bundle["statement"], bundle["attestation"]]
            for _ in range(rng.randint(1, 3)):
                target = rng.choice(targets)
                keys = list(target) + ([] if target is bundle else ["zzz"])      # unknown TOP-LEVEL keys are ignored and carry no trust
                key = rng.choice(keys); new = fuzz.rand_json(rng)
                if target.get(key, object()) != new:
                    target[key] = new; changed = True
            if changed:
                self.assertTrue(proof.bundle_errors(bundle, trust, "ci", self.head), "undetected mutation")

    def test_hostile_trust_stores_never_raise_and_never_verify(self):
        self.check(); private, _ = self.keys()
        sh(*CLI, "attest", "--key", str(private), "--principal", "ci", cwd=self.repo)
        bundle = json.loads((self.state / "proof.json").read_text())
        hostile = ["[]", "{", '{"version": 2}', '{"version": 2, "signers": []}', '{"ci": "x"}', '{"ci": [1]}', '{"ci": ["!!!"]}',
                   json.dumps({"version": 2, "signers": {"ci": [{"public_key": "AAAA"}]}}), "[" * 50000, '{"ci": ["' + "A" * 2_000_000 + '"]}']
        for i, text in enumerate(hostile):
            path = self.outside / f"hostile{i}.json"; path.write_text(text)
            with self.subTest(i=i): self.assertTrue(proof.bundle_errors(bundle, path, "ci", self.head))


try:
    import hypothesis  # noqa: F401
    from hypothesis import given, settings, strategies as st
except ImportError:  # pragma: no cover
    hypothesis = None


@unittest.skipUnless(hypothesis, "optional: pip install hypothesis")
class HypothesisProperties(unittest.TestCase):
    if hypothesis:
        json_values = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=40), lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4), max_leaves=20)

        @settings(max_examples=300, deadline=None)
        @given(json_values)
        def test_validate_contracts_is_total(self, value):
            try:
                trustdiff.validate_contracts(value)
            except ValueError:
                pass

        @settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=200))
        def test_name_status_parser_is_total(self, blob):
            self.assertIsInstance(safe.parse_name_status_z(blob), list)

        @settings(max_examples=200, deadline=None)
        @given(st.text(max_size=300))
        def test_clip_is_bounded(self, text):
            self.assertLessEqual(len(ev.clip(text)), ev.MAX_STRING)


if __name__ == "__main__":
    unittest.main()
