"""Verifier identity: a reproducible digest over the exact code that performs verification.

The gate must run a verifier whose digest was approved OUTSIDE the branch under test
(an organisation-level variable, a protected reusable workflow input, or a signed release).
A pull request can change files in its own tree, but not the approved digest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

# Single source of truth. The GitHub workflow extracts exactly these files from the trusted base commit.
VERIFIER_FILES = (
    "trustdiff.py", "trustdiff_impact.py", "trustdiff_challenge.py", "trustdiff_runner.py",
    "trustdiff_proof.py", "trustdiff_safe.py", "trustdiff_evidence.py", "trustdiff_store.py", "trustdiff_supply.py", "trustdiff_repair.py",
)
MANIFEST_VERSION = 1


def verifier_manifest(directory: Path | None = None) -> dict:
    base = Path(directory) if directory else Path(__file__).resolve().parent
    files = {}
    for name in VERIFIER_FILES:
        path = base / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"verifier file missing or not a regular file: {name}")
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    canonical = json.dumps({"version": MANIFEST_VERSION, "files": files}, sort_keys=True, separators=(",", ":")).encode()
    return {"version": MANIFEST_VERSION, "files": files, "manifest_sha256": hashlib.sha256(canonical).hexdigest()}


def verifier_digest(directory: Path | None = None) -> str:
    return verifier_manifest(directory)["manifest_sha256"]


def check_cmd(args: argparse.Namespace) -> int:
    try:
        manifest = verifier_manifest(Path(args.dir) if args.dir else None)
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    expected = args.expect or os.environ.get("TRUSTDIFF_VERIFIER_SHA256", "")
    ok = (manifest["manifest_sha256"] == expected.lower()) if expected else None
    print(json.dumps({"manifest_sha256": manifest["manifest_sha256"], "matches_expected": ok, "files": manifest["files"]}, indent=2))
    if args.expect or args.require:
        return 0 if ok else 1
    return 0


def add_commands(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("verifier-digest", help="Print (and optionally enforce) the digest of this verifier's code")
    p.add_argument("--dir", help="Directory containing the verifier modules (default: this installation)")
    p.add_argument("--expect", help="Required SHA-256; exit 1 on mismatch. Falls back to $TRUSTDIFF_VERIFIER_SHA256 with --require")
    p.add_argument("--require", action="store_true", help="Fail unless a digest is supplied and matches")
    p.set_defaults(func=check_cmd)
