import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(ROOT / "trustdiff.py")]


class TrustDiffPrototypeTests(unittest.TestCase):
    def test_init_creates_config(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=d, check=True)
            p = subprocess.run(CLI + ["init"], cwd=d, text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue((Path(d) / ".trustdiff/config.json").exists())

    def test_unauthorized_execution_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=d, check=True)
            (Path(d) / "trustdiff.contracts.json").write_text(json.dumps({"contracts": [{"id": "T", "type": "test", "command": ["python3", "-c", "print(1)"]}]}))
            subprocess.run(["git", "add", "."], cwd=d, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base"], cwd=d, check=True)
            p = subprocess.run(CLI + ["check"], cwd=d, text=True, capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            report = json.loads((Path(d) / ".trustdiff/latest.json").read_text())
            self.assertEqual(report["results"][0]["verdict"], "ERROR")


if __name__ == "__main__":
    unittest.main()
