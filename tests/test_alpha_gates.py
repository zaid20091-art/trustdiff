import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import trustdiff

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(ROOT / "trustdiff.py")]


def write_chain(state: Path, count=2):
    evidence = state / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    lines = []
    previous = "GENESIS"
    for i in range(count):
        report = {"run": i, "verdict": "PASS"}
        raw = json.dumps(report, sort_keys=True, ensure_ascii=False).encode()
        report_hash = hashlib.sha256(raw).hexdigest()
        (evidence / f"{report_hash}.json").write_bytes(raw)
        payload = {"previous_hash": previous, "record_type": "verification", "report_hash": report_hash}
        entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        entry = {**payload, "entry_hash": entry_hash}
        lines.append(entry)
        previous = entry_hash
    (state / "ledger.jsonl").write_text("\n".join(json.dumps(x, sort_keys=True) for x in lines) + "\n")
    (state / "ledger.anchor.json").write_text(json.dumps({"entry_count": len(lines), "head_hash": lines[-1]["entry_hash"]}))


class AlphaGateTests(unittest.TestCase):
    def test_empty_contracts_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=d, check=True)
            (root / "trustdiff.contracts.json").write_text('{"contracts": []}')
            subprocess.run(["git", "add", "."], cwd=d, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base"], cwd=d, check=True)
            p = subprocess.run(CLI + ["check"], cwd=d, text=True, capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            report = json.loads((root / ".trustdiff/latest.json").read_text())
            self.assertEqual(report["verification_guard"]["verdict"], "ERROR")

    def test_waived_is_not_technical_claim_pass(self):
        with tempfile.TemporaryDirectory() as d:
            claims = Path(d) / "claims.json"
            claims.write_text(json.dumps({"claims": [{"claim_id": "C", "requirements": ["A"]}]}))
            result = trustdiff.verify_claims(claims, [{"contract_id": "A", "verdict": "WAIVED"}])
            self.assertEqual(result[0]["verdict"], "UNKNOWN")
            self.assertIn("not technical proof", result[0]["explanation"])

    def test_ledger_detects_tamper_delete_and_reorder(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            original = trustdiff.STATE
            try:
                trustdiff.STATE = state
                write_chain(state, 2)
                self.assertTrue(trustdiff.verify_ledger()["valid"])
                lines = (state / "ledger.jsonl").read_text().splitlines()
                tampered = json.loads(lines[0]); tampered["record_type"] = "rewritten"
                (state / "ledger.jsonl").write_text(json.dumps(tampered) + "\n" + lines[1] + "\n")
                self.assertFalse(trustdiff.verify_ledger()["valid"])
                write_chain(state, 2)
                (state / "ledger.jsonl").write_text(lines[0] + "\n")
                self.assertFalse(trustdiff.verify_ledger()["valid"])
                write_chain(state, 2)
                (state / "ledger.jsonl").write_text(lines[1] + "\n" + lines[0] + "\n")
                self.assertFalse(trustdiff.verify_ledger()["valid"])
            finally:
                trustdiff.STATE = original


if __name__ == "__main__":
    unittest.main()
