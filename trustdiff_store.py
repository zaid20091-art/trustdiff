"""Append-only, content-addressed evidence store with a hash-chained log.

Point `--store` at storage the candidate and the coding agent cannot write to (a bucket with Object Lock,
a WORM volume, a separate service). This module provides the write-once semantics and verification; on a
plain writable directory it is tamper-EVIDENT only, exactly like the local ledger.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

MAX_BUNDLE = 20 * 1024 * 1024


class StoreError(ValueError):
    pass


def _log_line(prev: str, digest: str, meta: dict) -> tuple[str, str]:
    body = {"previous": prev, "object": digest, **meta}
    entry = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return json.dumps({**body, "entry_hash": entry}, sort_keys=True), entry


def publish(bundle: Path, store: Path) -> dict:
    raw = bundle.read_bytes()
    if len(raw) > MAX_BUNDLE:
        raise StoreError("bundle exceeds size limit")
    data = json.loads(raw)                                  # must at least be JSON
    digest = hashlib.sha256(raw).hexdigest()
    store.mkdir(parents=True, exist_ok=True)
    (store / "objects").mkdir(exist_ok=True)
    target = store / "objects" / f"{digest}.json"
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)   # write-once: never overwrites
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    except FileExistsError:
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise StoreError("existing object does not match its name: store is corrupt")
    log = store / "log.jsonl"
    previous = "GENESIS"
    if log.exists():
        lines = log.read_text(encoding="utf-8").splitlines()
        previous = json.loads(lines[-1])["entry_hash"] if lines else "GENESIS"
    statement = data.get("statement", {}) if isinstance(data, dict) else {}
    subject = statement.get("subject", [{}])[0] if isinstance(statement.get("subject"), list) and statement.get("subject") else {}
    meta = {"kind": "proof-bundle", "subject": subject.get("digest", {}) if isinstance(subject, dict) else {}}
    line, entry = _log_line(previous, digest, meta)
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return {"object": digest, "log_entry": entry, "store": str(store)}


def verify_store(store: Path) -> dict:
    errors: list[str] = []
    previous = "GENESIS"
    entries = 0
    log = store / "log.jsonl"
    seen: set[str] = set()
    if log.exists():
        for n, line in enumerate(log.read_text(encoding="utf-8").splitlines(), 1):
            try:
                entry = json.loads(line)
                claimed = entry.pop("entry_hash")
                recomputed = hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            except (ValueError, KeyError, AttributeError):
                errors.append(f"log line {n}: malformed"); continue
            if recomputed != claimed: errors.append(f"log line {n}: entry hash mismatch")
            if entry.get("previous") != previous: errors.append(f"log line {n}: does not link to the previous entry")
            obj = store / "objects" / f"{entry.get('object')}.json"
            if not obj.is_file(): errors.append(f"log line {n}: object missing")
            elif hashlib.sha256(obj.read_bytes()).hexdigest() != entry.get("object"): errors.append(f"log line {n}: object content altered")
            seen.add(str(entry.get("object")))
            previous = claimed; entries += 1
    objects = store / "objects"
    if objects.is_dir():
        for obj in objects.glob("*.json"):
            if obj.stem not in seen: errors.append(f"object {obj.stem[:12]} is not recorded in the log")
    return {"valid": not errors, "entries": entries, "errors": errors, "head": previous,
            "limitation": "Tamper-evident only unless the store is on write-once storage controlled by a separate party; pin `head` externally."}


def _outside_cwd(path: Path) -> None:
    if path.resolve().is_relative_to(Path.cwd().resolve()):
        raise StoreError("the evidence store must live outside the repository under verification")


def publish_cmd(args: argparse.Namespace) -> int:
    try:
        _outside_cwd(Path(args.store))
        print(json.dumps(publish(Path(args.bundle), Path(args.store)), indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 1


def verify_cmd(args: argparse.Namespace) -> int:
    result = verify_store(Path(args.store))
    if args.expect_head and args.expect_head != result["head"]:
        result["valid"] = False; result["errors"].append("log head differs from the externally pinned head")
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def add_commands(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("publish-evidence", help="Append a proof bundle to a write-once evidence store")
    p.add_argument("--bundle", required=True); p.add_argument("--store", required=True); p.set_defaults(func=publish_cmd)
    v = sub.add_parser("verify-evidence-store", help="Verify the store's hash-chained log and objects")
    v.add_argument("--store", required=True); v.add_argument("--expect-head", help="Externally pinned log head"); v.set_defaults(func=verify_cmd)
