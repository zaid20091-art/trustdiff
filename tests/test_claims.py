import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(ROOT / "trustdiff.py")]


class ClaimsAndLedgerTests(unittest.TestCase):
    def test_claim_without_evidence_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=d, check=True)
            (root / "trustdiff.contracts.json").write_text(json.dumps({"contracts": []}))
            (root / "claims.json").write_text(json.dumps({"claims": [{"claim_id": "C1", "agent": "a", "claim": "done", "requirements": ["MISSING"]}]}))
            subprocess.run(["git", "add", "."], cwd=d, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base"], cwd=d, check=True)
            subprocess.run(CLI + ["check", "--claims", "claims.json"], cwd=d, check=False)
            report = json.loads((root / ".trustdiff/latest.json").read_text())
            self.assertEqual(report["claims"][0]["verdict"], "UNKNOWN")
            self.assertEqual(len((root / ".trustdiff/ledger.jsonl").read_text().splitlines()), 1)

    def test_ledger_appends(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=d, check=True)
            (Path(d) / "trustdiff.contracts.json").write_text(json.dumps({"contracts": []}))
            subprocess.run(["git", "add", "."], cwd=d, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base"], cwd=d, check=True)
            subprocess.run(CLI + ["check"], cwd=d, check=False)
            subprocess.run(CLI + ["check"], cwd=d, check=False)
            lines = (Path(d) / ".trustdiff/ledger.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[1])["previous_hash"], json.loads(lines[0])["entry_hash"])


if __name__ == "__main__":
    unittest.main()
