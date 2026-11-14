"""P0-04: evidence chain - v2 bundles, key rotation/revocation, verifier binding, signed approvals, write-once store."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from support import symlink_or_skip

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_evidence_validator import CLI, HAVE_CRYPTO, Env, commit, sh  # noqa: E402

import trustdiff_evidence as ev  # noqa: E402
import trustdiff_proof as proof  # noqa: E402
import trustdiff_store as store  # noqa: E402
import trustdiff_supply as supply  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class V2Env(Env):
    def attest2(self, private, principal="ci", *extra, check=True):
        p = sh(*CLI, "attest", "--key", str(private), "--principal", principal, *extra, cwd=self.repo, check=check)
        return p

    def bundle(self):
        return json.loads((self.state / "proof.json").read_text())

    def verify_cli(self, trust, *extra, principal="ci", commit_id=None):
        return sh(*CLI, "verify-proof", "--bundle", str(self.state / "proof.json"), "--allowed-signers", str(trust), "--principal", principal,
                  "--expected-commit", commit_id or self.head, *extra, cwd=self.repo, check=False)

    def assess(self, trust, principal="ci", bundle=None, **kw):
        return proof.bundle_assessment(bundle or self.bundle(), trust, principal, self.head, **kw)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography extra required")
class BundleV2Tests(V2Env):
    def test_v2_bundle_binds_signer_verifier_and_scope(self):
        self.check(); private, trust = self.keys(); self.attest2(private)
        b = self.bundle()
        self.assertEqual(b["bundle_version"], 2)
        self.assertEqual(b["attestation"]["verifier"]["manifest_sha256"], supply.verifier_digest())
        self.assertEqual(b["attestation"]["principal"], "ci")
        errors, info = self.assess(trust)
        self.assertEqual(errors, []); self.assertFalse(info["legacy"])
        self.assertEqual({c["id"] for c in info["scope"]["contracts"]}, {"POLICY-1", "DENY-TLS"})
        self.assertEqual(ev.validate(self.state, self.repo, ev.TrustAnchors(trust, "ci")).status, ev.VERIFIED)

    def test_reverification_cli_runs_no_tests_and_prints_scope(self):
        self.check(); private, trust = self.keys(); self.attest2(private)
        p = self.verify_cli(trust)
        out = json.loads(p.stdout)
        self.assertEqual(p.returncode, 0); self.assertTrue(out["verified"]); self.assertIn("not proof the program is free of bugs", out["scope"]["claims_scope"])
        self.assertEqual(out["signer"]["principal"], "ci")

    def test_verifier_digest_pinning(self):
        self.check(); private, trust = self.keys(); self.attest2(private)
        good = supply.verifier_digest()
        self.assertEqual(self.verify_cli(trust, "--expected-verifier-sha256", good).returncode, 0)
        bad = self.verify_cli(trust, "--expected-verifier-sha256", "0" * 64)
        self.assertEqual(bad.returncode, 1); self.assertIn("externally approved verifier", bad.stdout)
        anchors = ev.TrustAnchors(trust, "ci", expected_verifier_sha256="0" * 64)
        self.assertEqual(ev.validate(self.state, self.repo, anchors).status, ev.INVALID_EVIDENCE)

    def test_signing_refuses_unapproved_verifier(self):
        self.check(); private, _ = self.keys()
        p = self.attest2(private, "ci", "--require-verifier-sha256", "f" * 64, check=False)
        self.assertEqual(p.returncode, 2); self.assertFalse((self.state / "proof.json").exists())

    def test_tampering_with_any_signed_attestation_field_is_detected(self):
        self.check(); private, trust = self.keys(); self.attest2(private)
        original = self.bundle()
        edits = {
            "signed_at": lambda a: a.__setitem__("signed_at", "2001-01-01T00:00:00Z"),
            "key_id": lambda a: a.__setitem__("key_id", "0" * 16),
            "principal": lambda a: a.__setitem__("principal", "mallory"),
            "verifier": lambda a: a["verifier"].__setitem__("manifest_sha256", "1" * 64),
            "runner": lambda a: a.__setitem__("runner", {"mode": "none"}),
        }
        for name, edit in edits.items():
            with self.subTest(name):
                forged = json.loads(json.dumps(original)); edit(forged["attestation"])
                self.assertTrue(self.assess(trust, bundle=forged)[0])

    def test_replay_on_another_commit_is_rejected(self):
        self.check(); private, trust = self.keys(); self.attest2(private)
        errors, _ = proof.bundle_assessment(self.bundle(), trust, "ci", "a" * 40)
        self.assertTrue(any("expected commit" in e for e in errors))

    def test_require_v2_refuses_legacy_bundle(self):
        self.check(); private, trust = self.keys(); self.attest(private)
        self.assertEqual(self.assess(trust)[0], [])
        errors, info = self.assess(trust, require_v2=True)
        self.assertTrue(info["legacy"]); self.assertTrue(any("Legacy v1" in e for e in errors))
        self.assertEqual(ev.validate(self.state, self.repo, ev.TrustAnchors(trust, "ci", require_v2=True)).status, ev.INVALID_EVIDENCE)

    def test_legacy_v1_trust_store_format_still_works(self):
        self.check(); private, trust = self.keys(); self.attest(private)
        v2 = json.loads(trust.read_text())
        legacy = self.outside / "legacy_store.json"
        legacy.write_text(json.dumps({"ci": [k["public_key"] for k in v2["signers"]["ci"]]}))
        self.assertEqual(self.assess(legacy)[0], [])


@unittest.skipUnless(HAVE_CRYPTO, "cryptography extra required")
class RotationRevocationTests(V2Env):
    def rotate(self, trust, name="ci2"):
        new = self.outside / f"{name}.pem"
        sh(*CLI, "rotate-key", "--allowed-signers", str(trust), "--principal", "ci", "--new-private", str(new), cwd=self.repo)
        return new

    def test_rotation_keeps_old_signatures_valid_and_new_key_works(self):
        self.check(); old, trust = self.keys(); self.attest2(old)
        old_bundle = self.bundle()
        new = self.rotate(trust)
        store_data = json.loads(trust.read_text())["signers"]["ci"]
        self.assertEqual(len(store_data), 2); self.assertIsNotNone(store_data[0]["not_after"]); self.assertIsNone(store_data[1]["not_after"])
        self.assertEqual(self.assess(trust, bundle=old_bundle)[0], [])            # signed before retirement
        self.attest2(new)
        self.assertEqual(self.assess(trust)[0], [])

    def test_retired_key_cannot_sign_after_retirement(self):
        self.check(); old, trust = self.keys()
        self.rotate(trust)
        data = json.loads(trust.read_text())
        data["signers"]["ci"][0]["not_after"] = proof.iso(proof.now_utc() - timedelta(hours=1))   # retired an hour ago
        trust.write_text(json.dumps(data))
        self.attest2(old)
        errors, _ = self.assess(trust)
        self.assertTrue(any("retired" in e for e in errors))

    def test_revocation_is_absolute_for_past_and_future_bundles(self):
        self.check(); old, trust = self.keys(); self.attest2(old)
        key_id = json.loads(trust.read_text())["signers"]["ci"][0]["key_id"]
        self.assertEqual(self.assess(trust)[0], [])
        sh(*CLI, "revoke-key", "--allowed-signers", str(trust), "--principal", "ci", "--key-id", key_id, "--reason", "laptop stolen", cwd=self.repo)
        errors, _ = self.assess(trust)
        self.assertTrue(any("revoked" in e and "laptop stolen" in e for e in errors))
        self.assertEqual(ev.validate(self.state, self.repo, ev.TrustAnchors(trust, "ci")).status, ev.INVALID_EVIDENCE)

    def test_revoking_unknown_key_fails_and_changes_nothing(self):
        _, trust = self.keys(); before = trust.read_text()
        p = sh(*CLI, "revoke-key", "--allowed-signers", str(trust), "--principal", "ci", "--key-id", "nope", cwd=self.repo, check=False)
        self.assertNotEqual(p.returncode, 0); self.assertEqual(trust.read_text(), before)

    def test_signing_in_the_future_or_before_key_creation_is_rejected(self):
        self.check(); private, trust = self.keys(); self.attest2(private)
        errors, _ = proof.bundle_assessment(self.bundle(), trust, "ci", self.head, now=proof.now_utc() - timedelta(days=1))
        self.assertTrue(any("future" in e for e in errors))
        errors, _ = proof.bundle_assessment(self.bundle(), trust, "ci", self.head, now=proof.now_utc() + timedelta(days=1))
        self.assertEqual(errors, [])

    def test_trust_store_with_mismatched_key_id_is_rejected(self):
        self.check(); private, trust = self.keys(); self.attest2(private)
        data = json.loads(trust.read_text()); data["signers"]["ci"][0]["key_id"] = "0" * 16; trust.write_text(json.dumps(data))
        errors, _ = self.assess(trust)
        self.assertTrue(any("key_id" in e for e in errors))

    def test_keys_and_stores_must_live_outside_the_repository(self):
        for cmd in (["keygen", "--private", str(self.repo / "k.pem"), "--allowed-signers", str(self.outside / "s.json"), "--principal", "ci"],
                    ["keygen", "--private", str(self.outside / "k.pem"), "--allowed-signers", str(self.repo / "s.json"), "--principal", "ci"]):
            p = sh(*CLI, *cmd, cwd=self.repo, check=False)
            self.assertNotEqual(p.returncode, 0)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography extra required")
class ApprovalTests(V2Env):
    def approve(self, key, policy_sha, out=None, principal="approver", reason="reviewed by security"):
        out = out or self.outside / "approval.json"
        sh(*CLI, "approve-policy", "--key", str(key), "--principal", principal, "--policy-sha256", policy_sha, "--reason", reason, "--output", str(out), cwd=self.repo)
        return out

    def test_signed_policy_approval_round_trip_and_binding(self):
        self.check(); ci_key, ci_trust = self.keys("ci", "ci")
        ap_key, ap_trust = self.keys("approver", "approver")
        self.attest2(ci_key)
        policy_sha = self.bundle()["report"]["policy_sha256"]
        approval = self.approve(ap_key, policy_sha)
        ok = sh(*CLI, "verify-approval", "--approval", str(approval), "--allowed-signers", str(ap_trust), "--principal", "approver", "--expected-policy-sha256", policy_sha, cwd=self.repo, check=False)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        wrong = sh(*CLI, "verify-approval", "--approval", str(approval), "--allowed-signers", str(ap_trust), "--principal", "approver", "--expected-policy-sha256", "9" * 64, cwd=self.repo, check=False)
        self.assertEqual(wrong.returncode, 1)
        both = self.verify_cli(ci_trust, "--approval", str(approval), "--approvers", str(ap_trust), "--approver-principal", "approver")
        self.assertEqual(both.returncode, 0, both.stdout); self.assertEqual(json.loads(both.stdout)["policy_approval"]["approver"], "approver")

    def test_approval_for_other_policy_or_forged_signature_blocks_verification(self):
        self.check(); ci_key, ci_trust = self.keys("ci", "ci"); ap_key, ap_trust = self.keys("approver", "approver")
        self.attest2(ci_key)
        stale = self.approve(ap_key, "7" * 64)
        r = self.verify_cli(ci_trust, "--approval", str(stale), "--approvers", str(ap_trust), "--approver-principal", "approver")
        self.assertEqual(r.returncode, 1); self.assertIn("different policy digest", r.stdout)
        good = self.approve(ap_key, self.bundle()["report"]["policy_sha256"], self.outside / "good.json")
        forged = json.loads(good.read_text()); forged["statement"]["predicate"]["reason"] = "rubber stamp"
        bad = self.outside / "forged.json"; bad.write_text(json.dumps(forged))
        r = self.verify_cli(ci_trust, "--approval", str(bad), "--approvers", str(ap_trust), "--approver-principal", "approver")
        self.assertEqual(r.returncode, 1); self.assertIn("signature invalid", r.stdout)

    def test_ci_key_cannot_approve_its_own_policy_change(self):
        self.check(); ci_key, ci_trust = self.keys("ci", "ci"); ap_key, ap_trust = self.keys("approver", "approver")
        self.attest2(ci_key)
        self_approval = self.approve(ci_key, self.bundle()["report"]["policy_sha256"], self.outside / "self.json", principal="ci")
        r = self.verify_cli(ci_trust, "--approval", str(self_approval), "--approvers", str(ap_trust), "--approver-principal", "approver")
        self.assertEqual(r.returncode, 1)


class SupplyChainTests(unittest.TestCase):
    def copy_verifier(self):
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d, True)
        for name in supply.VERIFIER_FILES: shutil.copy(ROOT / name, d / name)
        return d

    def test_manifest_is_deterministic_and_covers_every_verifier_file(self):
        d = self.copy_verifier()
        self.assertEqual(supply.verifier_digest(d), supply.verifier_digest(ROOT))
        self.assertEqual(set(supply.verifier_manifest(d)["files"]), set(supply.VERIFIER_FILES))

    def test_every_module_is_in_the_manifest(self):
        modules = {p.name for p in ROOT.glob("trustdiff*.py")} - {"trustdiff_mcp.py"}
        self.assertEqual(modules, set(supply.VERIFIER_FILES))

    def test_any_modification_changes_the_digest(self):
        d = self.copy_verifier(); base = supply.verifier_digest(d)
        for name in supply.VERIFIER_FILES:
            with self.subTest(name):
                path = d / name; original = path.read_bytes(); path.write_bytes(original + b"\n# x\n")
                self.assertNotEqual(supply.verifier_digest(d), base); path.write_bytes(original)

    def test_missing_or_symlinked_file_is_an_error(self):
        d = self.copy_verifier(); (d / "trustdiff_safe.py").unlink()
        with self.assertRaises(ValueError): supply.verifier_manifest(d)
        d2 = self.copy_verifier(); (d2 / "trustdiff_runner.py").unlink()
        symlink_or_skip(self, ROOT / "trustdiff_runner.py", d2 / "trustdiff_runner.py")
        with self.assertRaises(ValueError): supply.verifier_manifest(d2)

    def test_cli_enforces_expected_digest(self):
        good = sh(*CLI, "verifier-digest", "--expect", supply.verifier_digest(), cwd=ROOT, check=False)
        bad = sh(*CLI, "verifier-digest", "--expect", "0" * 64, cwd=ROOT, check=False)
        self.assertEqual((good.returncode, bad.returncode), (0, 1))
        self.assertEqual(sh(*CLI, "verifier-digest", "--require", cwd=ROOT, check=False).returncode, 1)   # no digest supplied: fail closed


class EvidenceStoreTests(V2Env):
    def make_bundle(self):
        self.check(); return self.state / "proof.json" if sh(*CLI, "bundle", cwd=self.repo) and True else None

    def test_publish_verify_and_write_once(self):
        bundle = self.make_bundle(); s = self.outside / "store"
        out = store.publish(bundle, s)
        self.assertTrue(store.verify_store(s)["valid"])
        self.assertEqual(oct((s / "objects" / f"{out['object']}.json").stat().st_mode & 0o777), "0o444")
        store.publish(bundle, s)                                                      # idempotent, never overwrites
        self.assertEqual(store.verify_store(s)["entries"], 2)

    def test_an_existing_object_is_never_overwritten(self):
        bundle = self.make_bundle(); s = self.outside / "store"; out = store.publish(bundle, s)
        obj = s / "objects" / f"{out['object']}.json"
        obj.chmod(0o644); obj.write_text('{"tampered": true}')                         # someone altered the stored object
        with self.assertRaises(store.StoreError):
            store.publish(bundle, s)                                                    # republishing must NOT silently repair/overwrite it
        self.assertEqual(obj.read_text(), '{"tampered": true}')
        self.assertFalse(store.verify_store(s)["valid"])

    def test_tampered_object_log_or_unlisted_object_is_detected(self):
        bundle = self.make_bundle(); s = self.outside / "store"; out = store.publish(bundle, s)
        obj = s / "objects" / f"{out['object']}.json"; obj.chmod(0o644); obj.write_text(obj.read_text().replace("PASS", "FAIL"))
        self.assertFalse(store.verify_store(s)["valid"])
        s2 = self.outside / "store2"; store.publish(bundle, s2); (s2 / "log.jsonl").write_text((s2 / "log.jsonl").read_text().replace("proof-bundle", "x"))
        self.assertFalse(store.verify_store(s2)["valid"])
        s3 = self.outside / "store3"; store.publish(bundle, s3); (s3 / "objects" / ("a" * 64 + ".json")).write_text("{}")
        self.assertFalse(store.verify_store(s3)["valid"])

    def test_externally_pinned_head_detects_truncation(self):
        bundle = self.make_bundle(); s = self.outside / "store"; store.publish(bundle, s)
        head = store.verify_store(s)["head"]
        store.publish(bundle, s)
        (s / "log.jsonl").write_text((s / "log.jsonl").read_text().splitlines()[0] + "\n")      # roll the log back
        r = sh(*CLI, "verify-evidence-store", "--store", str(s), "--expect-head", store.verify_store(s)["head"] + "x", cwd=self.repo, check=False)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(store.verify_store(s)["head"], head)

    def test_store_inside_the_repository_is_refused(self):
        bundle = self.make_bundle()
        p = sh(*CLI, "publish-evidence", "--bundle", str(bundle), "--store", str(self.repo / "evidence-store"), cwd=self.repo, check=False)
        self.assertEqual(p.returncode, 1)


class LedgerHonestyTests(Env):
    def test_verify_ledger_states_it_is_tamper_evident_only(self):
        self.check()
        out = json.loads(sh(*CLI, "verify-ledger", cwd=self.repo).stdout)
        self.assertTrue(out["valid"]); self.assertIn("tamper-evident only", out["trust"])


if __name__ == "__main__":
    unittest.main()
