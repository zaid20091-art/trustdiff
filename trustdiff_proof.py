"""Portable proof bundles using in-toto Statements and externally trusted Ed25519 signatures.

The signer must be controlled by a separate verifier, not the coding agent.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

NAMESPACE = "trustdiff-proof-v1@trustdiff.dev"
PREDICATE = "https://trustdiff.dev/attestation/verification/v1"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def report_digest(report: dict[str, Any]) -> str:
    # Identical to the archived report's content encoding in trustdiff.py.
    return hashlib.sha256(report_bytes(report)).hexdigest()


def report_bytes(report: dict[str, Any]) -> bytes:
    return json.dumps(report, sort_keys=True, ensure_ascii=False).encode("utf-8", "backslashreplace")


def _str_in(value: Any, allowed: set[str]) -> bool:
    return isinstance(value, str) and value in allowed


def valid_repository(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", value)) and all(
        part not in {".", ".."} for part in value.split("/")
    )


def _dict_items(report: dict[str, Any], key: str, errors: list[str]) -> list[dict[str, Any]]:
    """Return report[key] only if it is a list of objects; malformed input is an error, never a crash."""
    value = report.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        errors.append("Malformed report field: " + key)
        return []
    return value


def proof_errors(report: dict[str, Any], allow_failure: bool = False) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["Report is not a JSON object"]
    failure = allow_failure and report.get("overall_verdict") == "FAIL"
    if (report.get("overall_verdict") != "PASS" and not failure) or report.get("integrity_verdict") != "PASS":
        errors.append("Overall or integrity verdict is not PASS")
    if report.get("verification_guard") and not failure:
        errors.append("Verification guard is not clear")
    results = _dict_items(report, "results", errors)
    if not failure and (not results or not any(r.get("verdict") == "PASS" for r in results)):
        errors.append("No passing contract")
    for r in results:
        if not failure and r.get("verdict") != "PASS": errors.append("Non-PASS contract: " + str(r.get("contract_id")))
    if any(c.get("verdict") != "PASS" for c in _dict_items(report, "claims", errors)) and not failure:
        errors.append("A claim is not independently proven")
    if any(g.get("level") == "critical" for g in _dict_items(report, "coverage_gaps", errors)) and not failure:
        errors.append("Critical risk lacks a passing coverage contract")
    if not _str_in(report.get("policy_source"), {"baseline", "committed"}):
        errors.append("Contracts are not anchored to a Git commit")
    if report.get("policy_drift"):
        errors.append("Contract or gate policy changed")
    if report.get("git_config_audit") == "overridden":
        errors.append("Git configuration audit was overridden")
    if not report.get("clean_worktree"):
        errors.append("Worktree was dirty; evidence cannot be bound to just the commit")
    snapshot = report.get("input_snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("fingerprint") is None:
        errors.append("Missing captured inputs")
    config = report.get("runner_config")
    if isinstance(config, dict) and config.get("mode") == "host":
        errors.append("Execution was not isolated")
    for ev in _dict_items(report, "evidence", errors):
        if _str_in(ev.get("method"), {"test", "challenge", "counterexample"}):
            runner = ev.get("runner")
            runner = runner if isinstance(runner, dict) else {}
            if runner.get("mode") != "docker": errors.append("Execution was not isolated")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}", str(runner.get("image", ""))):
                errors.append("Runner image is not pinned by digest")
    return errors


def make_statement(report: dict[str, Any]) -> dict[str, Any]:
    target = report.get("target_commit", "")
    algorithm = "sha1" if len(target) == 40 else "sha256" if len(target) == 64 else "unknown"
    if algorithm == "unknown" or any(c not in "0123456789abcdef" for c in target):
        raise ValueError("Invalid target Git object ID")
    subject = {"name": "git-commit", "digest": {algorithm: target}}
    if "repository" in report:
        repository = report["repository"]
        if not isinstance(repository, str) or not valid_repository(repository) or repository != repository.lower():
            raise ValueError("Invalid repository binding")
        subject["name"] = "git-commit:" + repository
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [subject],
        "predicateType": PREDICATE,
        "predicate": {
            "report_sha256": report_digest(report),
            "baseline_commit": report.get("baseline_commit"),
            "policy_sha256": report.get("policy_sha256"),
            "overall_verdict": report.get("overall_verdict"),
            "worktree_sha256": report.get("worktree_fingerprint_before"),
            "generated_at": report.get("generated_at"),
            "runner": report.get("runner_config"),
            "trust_boundary": "An independent signer and externally pinned policy are required for third-party trust",
        },
    }


NAMESPACE_V2 = "trustdiff-proof-v2@trustdiff.dev"
APPROVAL_NAMESPACE = "trustdiff-approval-v1@trustdiff.dev"
APPROVAL_PREDICATE = "https://trustdiff.dev/attestation/policy-approval/v1"
SKEW = timedelta(minutes=5)
MAX_JSON = 20 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- time + files

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp must be an ISO-8601 string")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must carry a UTC offset")
    return parsed.astimezone(timezone.utc)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON object key")
    return value


def _read_json(path: Path, limit: int = MAX_JSON) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path.name}: not a regular file")
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"{path.name}: exceeds the {limit} byte limit")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=lambda c: (_ for _ in ()).throw(ValueError("non-finite number")))


def _assert_outside_repo(*paths: Path) -> None:
    for path in paths:
        if path.resolve().is_relative_to(Path.cwd().resolve()):
            raise ValueError("Keep signing keys AND trust stores outside the repository")


# --------------------------------------------------------------------------- trust store (v1 legacy + v2 with rotation/revocation)

@dataclass(frozen=True)
class SignerKey:
    key_id: str
    public_key: bytes
    not_before: datetime | None = None
    not_after: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


def key_id_of(raw_public: bytes) -> str:
    return hashlib.sha256(raw_public).hexdigest()[:16]


def _b64_key(encoded: Any) -> bytes:
    raw = base64.b64decode(encoded, validate=True) if isinstance(encoded, str) else b""
    if len(raw) != 32:
        raise ValueError("public keys must be 32-byte Ed25519 keys encoded as base64")
    return raw


def load_trust_store(path: Path) -> dict[str, list[SignerKey]]:
    data = _read_json(Path(path), 1_000_000)
    if not isinstance(data, dict):
        raise ValueError("trust store must be a JSON object")
    out: dict[str, list[SignerKey]] = {}
    if data.get("version") == 2:
        signers = data.get("signers")
        if not isinstance(signers, dict):
            raise ValueError("trust store v2 needs a signers object")
        for principal, entries in signers.items():
            if not isinstance(entries, list) or len(entries) > 100:
                raise ValueError("signer entries must be a list")
            keys = []
            for e in entries:
                if not isinstance(e, dict):
                    raise ValueError("signer entry must be an object")
                raw = _b64_key(e.get("public_key"))
                if e.get("key_id") != key_id_of(raw):
                    raise ValueError("key_id does not match the public key")
                opt = lambda k: parse_ts(e[k]) if e.get(k) else None
                keys.append(SignerKey(e["key_id"], raw, opt("not_before"), opt("not_after"), opt("revoked_at"), str(e.get("revoked_reason") or "")[:300] or None))
            out[str(principal)] = keys
        return out
    for principal, entries in data.items():  # v1: {principal: [base64 key, ...]}
        if not isinstance(entries, list) or any(not isinstance(x, str) for x in entries):
            raise ValueError("legacy trust store must map principals to lists of base64 keys")
        out[str(principal)] = [SignerKey(key_id_of(_b64_key(x)), _b64_key(x)) for x in entries]
    return out


def write_trust_store(path: Path, store: dict[str, list[SignerKey]]) -> None:
    def encode(k: SignerKey) -> dict[str, Any]:
        return {"key_id": k.key_id, "public_key": base64.b64encode(k.public_key).decode(), "not_before": iso(k.not_before) if k.not_before else None,
                "not_after": iso(k.not_after) if k.not_after else None, "revoked_at": iso(k.revoked_at) if k.revoked_at else None, "revoked_reason": k.revoked_reason}
    payload = json.dumps({"version": 2, "signers": {p: [encode(k) for k in keys] for p, keys in store.items()}}, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)


def check_key_validity(key: SignerKey, signed_at: datetime | None, now: datetime) -> str | None:
    """Why this key may not vouch for a signature, or None. Revocation is absolute; windows apply to the signing time."""
    if key.revoked_at is not None:
        return "Signing key was revoked" + (f": {key.revoked_reason}" if key.revoked_reason else "")
    if signed_at is None:   # legacy v1: no signing time, so the window must hold NOW
        if key.not_before and now + SKEW < key.not_before:
            return "Signing key is not valid yet"
        if key.not_after and now - SKEW > key.not_after:
            return "Signing key was retired; a legacy bundle cannot prove it was signed before retirement"
        return None
    if signed_at > now + SKEW:
        return "Signature claims a signing time in the future"
    if key.not_before and signed_at < key.not_before - SKEW:
        return "Signed before the key became valid"
    if key.not_after and signed_at > key.not_after + SKEW:
        return "Signed after the key was retired"
    return None


# --------------------------------------------------------------------------- crypto primitives

def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        return serialization, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature
    except ImportError as exc:
        raise RuntimeError("Install the optional crypto extra: pip install 'trustdiff[crypto]'") from exc


def _load_private(key: Path):
    serialization, Private, _, _ = _crypto()
    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(private, Private):
        raise ValueError("Signing key must be a dedicated Ed25519 private key")
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, raw_public


def _signature(message: bytes, key: Path, namespace: str = NAMESPACE) -> str:
    private, _ = _load_private(key)
    return base64.b64encode(private.sign(namespace.encode() + b"\x00" + message)).decode("ascii")


def _verify_raw(raw_public: bytes, message: bytes, signature: str, namespace: str) -> bool:
    _, _, Public, InvalidSignature = _crypto()
    try:
        Public.from_public_bytes(raw_public).verify(base64.b64decode(signature, validate=True), namespace.encode() + b"\x00" + message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- bundle verification

def make_attestation(report: dict[str, Any], principal: str, key_id: str, signed_at: datetime, verifier_sha256: str) -> dict[str, Any]:
    import trustdiff
    snapshot = report.get("input_snapshot") if isinstance(report.get("input_snapshot"), dict) else {}
    return {
        "principal": principal, "key_id": key_id, "signed_at": iso(signed_at),
        "verifier": {"name": "trustdiff", "version": trustdiff.VERSION, "manifest_sha256": verifier_sha256},
        "target_commit": report.get("target_commit"), "baseline_commit": report.get("baseline_commit"),
        "policy_sha256": report.get("policy_sha256"), "runner": report.get("runner_config"),
        "environment": snapshot.get("environment") if isinstance(snapshot.get("environment"), dict) else None,
    }


def _scope(report: dict[str, Any]) -> dict[str, Any]:
    results = report.get("results") if isinstance(report.get("results"), list) else []
    return {
        "target_commit": report.get("target_commit"), "baseline_commit": report.get("baseline_commit"), "policy_sha256": report.get("policy_sha256"),
        "runner": report.get("runner_config"),
        "contracts": [{"id": str(r.get("contract_id"))[:200], "verdict": r.get("verdict")} for r in results[:200] if isinstance(r, dict)],
        "overall_verdict": report.get("overall_verdict"),
        "claims_scope": ("Only the listed contracts passed on the listed commit; this is not proof the program is free of bugs"
                         if report.get("overall_verdict") == "PASS"
                         else "The listed verdicts apply to the tested obligations on the listed commit"),
    }


def bundle_assessment(bundle: Any, allowed_signers: Path, principal: str, expected_commit: str | None, expected_policy_sha256: str | None = None,
                      expected_verifier_sha256: str | None = None, require_v2: bool = False, now: datetime | None = None) -> tuple[list[str], dict[str, Any]]:
    """(errors, info). Empty errors == verified. Fails closed on ANY malformed input."""
    errors: list[str] = []
    info: dict[str, Any] = {}
    now = now or now_utc()
    try:
        if not isinstance(bundle, dict):
            return ["Proof bundle is not a JSON object"], info
        report, statement = bundle.get("report"), bundle.get("statement")
        if not isinstance(report, dict) or not isinstance(statement, dict):
            return ["Proof bundle lacks a report or statement object"], info
        version = bundle.get("bundle_version")
        info.update(bundle_version=version, legacy=(version == 1), scope=_scope(report))
        if type(version) is not int or version not in (1, 2): errors.append("Unsupported bundle version")
        if statement != make_statement(report): errors.append("Statement/report binding mismatch")
        errors.extend(proof_errors(report, allow_failure=version == 2))
        if not expected_commit:
            errors.append("--expected-commit is mandatory to prevent proof replay")
        elif report.get("target_commit") != expected_commit:
            errors.append("Target commit does not match expected commit")
        if expected_policy_sha256 and report.get("policy_sha256") != expected_policy_sha256:
            errors.append("Policy digest differs from externally approved digest")
        signature = bundle.get("signature")
        candidates = load_trust_store(allowed_signers).get(principal, [])
        if not isinstance(signature, str) or not signature:
            errors.append("Unsigned or incorrect signature namespace")
        elif version == 2:
            attestation = bundle.get("attestation")
            if bundle.get("signature_namespace") != NAMESPACE_V2: errors.append("Unsigned or incorrect signature namespace")
            if not isinstance(attestation, dict):
                errors.append("Missing attestation")
            else:
                for field, expected in (("principal", principal), ("target_commit", report.get("target_commit")), ("policy_sha256", report.get("policy_sha256")), ("baseline_commit", report.get("baseline_commit"))):
                    if attestation.get(field) != expected: errors.append(f"Attestation {field} does not match the signed report")
                verifier = attestation.get("verifier") if isinstance(attestation.get("verifier"), dict) else {}
                vdigest = verifier.get("manifest_sha256")
                if not isinstance(vdigest, str) or not _HEX64.match(vdigest): errors.append("Attestation lacks a verifier digest")
                elif expected_verifier_sha256 and vdigest != expected_verifier_sha256.lower(): errors.append("Verifier digest differs from the externally approved verifier")
                signed_at = parse_ts(attestation.get("signed_at"))
                matching = [k for k in candidates if k.key_id == attestation.get("key_id")]
                if not matching:
                    errors.append("Signing key is not listed for this principal")
                else:
                    reason = check_key_validity(matching[0], signed_at, now)
                    if reason: errors.append(reason)
                    if not _verify_raw(matching[0].public_key, canonical({"statement": statement, "attestation": attestation}), signature, NAMESPACE_V2):
                        errors.append("Signature not authorized by allowed signers")
                info.update(key_id=attestation.get("key_id"), signed_at=attestation.get("signed_at"), verifier_sha256=vdigest, principal=principal)
        else:
            if bundle.get("signature_namespace") != NAMESPACE: errors.append("Unsigned or incorrect signature namespace")
            if require_v2: errors.append("Legacy v1 bundle refused: it has no signing time or verifier binding")
            if expected_verifier_sha256: errors.append("Legacy v1 bundle carries no verifier digest to compare")
            matched = next((k for k in candidates if _verify_raw(k.public_key, canonical(statement), signature, NAMESPACE)), None)
            if matched is None:
                errors.append("Signature not authorized by allowed signers")
            else:
                reason = check_key_validity(matched, None, now)
                if reason: errors.append(reason)
                info.update(key_id=matched.key_id, principal=principal)
    except Exception as exc:  # fail closed on ANY malformed input (AttributeError, RecursionError, ...)
        errors.append(f"Invalid proof: {type(exc).__name__}: {exc}")
    return errors, info


def bundle_errors(bundle: Any, allowed_signers: Path, principal: str, expected_commit: str | None, expected_policy_sha256: str | None = None,
                  expected_verifier_sha256: str | None = None, require_v2: bool = False) -> list[str]:
    """Every reason a proof bundle must NOT be trusted. Empty list == verified. Never raises on malformed input."""
    return bundle_assessment(bundle, allowed_signers, principal, expected_commit, expected_policy_sha256, expected_verifier_sha256, require_v2)[0]


# --------------------------------------------------------------------------- signed policy-approval records

def approval_assessment(envelope: Any, allowed_signers: Path, principal: str, expected_policy_sha256: str | None = None, now: datetime | None = None) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    info: dict[str, Any] = {}
    now = now or now_utc()
    try:
        if not isinstance(envelope, dict) or envelope.get("approval_version") != 1:
            return ["Not a version 1 approval record"], info
        statement, attestation, signature = envelope.get("statement"), envelope.get("attestation"), envelope.get("signature")
        if not isinstance(statement, dict) or not isinstance(attestation, dict) or not isinstance(signature, str):
            return ["Approval record is incomplete"], info
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        if statement.get("predicateType") != APPROVAL_PREDICATE: errors.append("Wrong predicate type")
        if envelope.get("signature_namespace") != APPROVAL_NAMESPACE: errors.append("Wrong signature namespace")
        if attestation.get("principal") != principal: errors.append("Approver principal mismatch")
        if predicate.get("approver") != principal: errors.append("Predicate approver differs from signer")
        if expected_policy_sha256 and predicate.get("policy_sha256") != expected_policy_sha256: errors.append("Approval is for a different policy digest")
        if not isinstance(predicate.get("policy_sha256"), str) or not _HEX64.match(predicate["policy_sha256"]): errors.append("Approval lacks a policy digest")
        keys = [k for k in load_trust_store(allowed_signers).get(principal, []) if k.key_id == attestation.get("key_id")]
        if not keys:
            errors.append("Approver key is not listed")
        else:
            reason = check_key_validity(keys[0], parse_ts(attestation.get("signed_at")), now)
            if reason: errors.append(reason)
            if not _verify_raw(keys[0].public_key, canonical({"statement": statement, "attestation": attestation}), signature, APPROVAL_NAMESPACE):
                errors.append("Approval signature invalid")
        info = {"approver": principal, "key_id": attestation.get("key_id"), "approved_at": attestation.get("signed_at"), "policy_sha256": predicate.get("policy_sha256"), "reason": str(predicate.get("reason", ""))[:300]}
    except Exception as exc:
        errors.append(f"Invalid approval: {type(exc).__name__}: {exc}")
    return errors, info


def approve_policy(args: argparse.Namespace) -> int:
    """Sign an approval for a specific policy digest. Run by the human/organisation approver, never by the coding agent."""
    _assert_outside_repo(Path(args.key))
    policy_sha = args.policy_sha256 or hashlib.sha256(Path(args.policy_file).read_bytes()).hexdigest()
    if not _HEX64.match(policy_sha): raise ValueError("policy digest must be 64 lowercase hex characters")
    if not args.reason or len(args.reason) > 1000: raise ValueError("a reason of at most 1000 characters is required")
    _, raw_public = _load_private(Path(args.key))
    moment = now_utc()
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "trustdiff-policy", "digest": {"sha256": policy_sha}}], "predicateType": APPROVAL_PREDICATE,
                 "predicate": {"policy_sha256": policy_sha, "policy_path": args.policy_path, "baseline_commit": args.baseline, "approver": args.principal, "reason": args.reason, "approved_at": iso(moment)}}
    attestation = {"principal": args.principal, "key_id": key_id_of(raw_public), "signed_at": iso(moment)}
    envelope = {"approval_version": 1, "statement": statement, "attestation": attestation, "signature_namespace": APPROVAL_NAMESPACE,
                "signature": _signature(canonical({"statement": statement, "attestation": attestation}), Path(args.key), APPROVAL_NAMESPACE)}
    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"approval": str(out), "policy_sha256": policy_sha, "key_id": attestation["key_id"]}, indent=2))
    return 0


def verify_approval(args: argparse.Namespace) -> int:
    try:
        errors, info = approval_assessment(_read_json(Path(args.approval)), Path(args.allowed_signers), args.principal, args.expected_policy_sha256)
    except Exception as exc:
        errors, info = [f"Invalid approval: {type(exc).__name__}: {exc}"], {}
    print(json.dumps({"verified": not errors, "errors": errors, "approval": info}, indent=2))
    return 0 if not errors else 1


# --------------------------------------------------------------------------- CLI: keys, packaging, verification

def keygen(args: argparse.Namespace) -> int:
    """Development-only helper. Production signer keys belong to an independent service."""
    serialization, Private, _, _ = _crypto()
    private_path, trust_path = Path(args.private), Path(args.allowed_signers)
    if private_path.exists() or trust_path.exists():
        raise ValueError("Refusing to overwrite an existing key or trust store")
    _assert_outside_repo(private_path, trust_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = Private.generate()
    payload = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file: file.write(payload)
    raw_pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    write_trust_store(trust_path, {args.principal: [SignerKey(key_id_of(raw_pub), raw_pub, not_before=now_utc() - SKEW)]})
    print(json.dumps({"private_key": str(private_path), "allowed_signers": str(trust_path), "principal": args.principal, "key_id": key_id_of(raw_pub), "warning": "Demo only: do not let the coding agent generate, access or approve a production signing key"}, indent=2))
    return 0


def rotate_key(args: argparse.Namespace) -> int:
    """Add a fresh signing key for a principal and retire the previous ones (their old signatures stay valid up to the retirement time)."""
    serialization, Private, _, _ = _crypto()
    store_path, new_private = Path(args.allowed_signers), Path(args.new_private)
    _assert_outside_repo(store_path, new_private)
    if new_private.exists(): raise ValueError("Refusing to overwrite an existing key")
    store = load_trust_store(store_path)
    moment = now_utc()
    keys = store.get(args.principal, [])
    if not args.keep_old:
        keys = [replace(k, not_after=moment) if (k.not_after is None and k.revoked_at is None) else k for k in keys]
    key = Private.generate()
    fd = os.open(new_private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    raw_pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    store[args.principal] = keys + [SignerKey(key_id_of(raw_pub), raw_pub, not_before=moment - SKEW)]
    write_trust_store(store_path, store)
    print(json.dumps({"principal": args.principal, "new_key_id": key_id_of(raw_pub), "retired": [k.key_id for k in keys if k.not_after == moment], "private_key": str(new_private)}, indent=2))
    return 0


def revoke_key(args: argparse.Namespace) -> int:
    """Hard-revoke a key: every bundle it signed, past or future, stops verifying."""
    store_path = Path(args.allowed_signers)
    _assert_outside_repo(store_path)
    store = load_trust_store(store_path)
    keys = store.get(args.principal, [])
    if not any(k.key_id == args.key_id for k in keys):
        raise ValueError("No such key for that principal")
    store[args.principal] = [replace(k, revoked_at=now_utc(), revoked_reason=(args.reason or "revoked")[:300]) if k.key_id == args.key_id else k for k in keys]
    write_trust_store(store_path, store)
    print(json.dumps({"revoked": args.key_id, "principal": args.principal}, indent=2))
    return 0


def package(args: argparse.Namespace) -> int:
    report = _read_json(Path(args.input))
    allow_failure = bool(args.key and args.principal and getattr(args, "include_failure", False))
    errors = proof_errors(report, allow_failure=allow_failure)
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    # Never package a report that was detached from its locally archived evidence.
    # Signed mode additionally requires repository/commit binding and a valid chain.
    if args.key:
        import trustdiff
        import trustdiff_safe
        trustdiff.ensure_safe_state()
        if os.environ.get("TRUSTDIFF_TRUST_GIT_CONFIG") == "1":
            raise ValueError("Git configuration override is incompatible with signing")
        trustdiff_safe.require_safe_git_config(trustdiff.ROOT)
        ledger_result = trustdiff.verify_ledger()
        if not ledger_result["valid"]:
            errors.append("Local evidence ledger is invalid")
        digest = report_digest(report)
        archive = trustdiff.STATE / "evidence" / (digest + ".json")
        archived_digest, _ = trustdiff_safe.regular_file_sha256(archive, limit=MAX_JSON)
        if not trustdiff_safe.is_regular_file(archive) or archived_digest != digest:
            errors.append("Report archive is missing or modified")
        if trustdiff.git_head() != report.get("target_commit"):
            errors.append("Repository HEAD differs from attested target commit")
        if not trustdiff._clean_worktree():
            errors.append("Repository worktree differs from the attested target commit")
        baseline = report.get("baseline_commit", "")
        policy_file = report.get("policy_path", "")
        if not isinstance(policy_file, str) or not trustdiff_safe.clean_repo_path(policy_file):
            errors.append("Invalid trusted contract policy path")
        else:
            rc, policy_bytes, _ = trustdiff_safe.run_git_bytes(trustdiff.ROOT, "show", f"{baseline}:{policy_file}", max_output=1_000_000)
            if rc or hashlib.sha256(policy_bytes).hexdigest() != report.get("policy_sha256"):
                errors.append("Policy digest is not anchored to the baseline trusted contract file")
        for field, expected in (("baseline_commit", getattr(args, "expected_baseline", None)),
                                ("target_commit", getattr(args, "expected_commit", None)),
                                ("repository", getattr(args, "expected_repository", None)),
                                ("policy_sha256", getattr(args, "expected_policy_sha256", None))):
            if expected is not None and report.get(field) != expected:
                errors.append(f"Report {field} differs from the verifier's approved input")
    if errors:
        print(json.dumps({"attestable": False, "errors": errors}, indent=2), file=sys.stderr)
        return 1
    if args.key and Path(args.key).resolve().is_relative_to(Path.cwd().resolve()):
        print("ERROR: signing key must be outside the evaluated repository", file=sys.stderr)
        return 2
    statement = make_statement(report)
    bundle: dict[str, Any] = {"bundle_version": 1, "statement": statement, "report": report, "signature": None, "signature_namespace": None}
    if args.key and getattr(args, "require_verifier_sha256", None) and not getattr(args, "principal", None):
        raise ValueError("An approved verifier digest requires a v2 signing principal")
    if args.key and getattr(args, "principal", None):
        import trustdiff_supply
        verifier = trustdiff_supply.verifier_digest()
        if getattr(args, "require_verifier_sha256", None) and args.require_verifier_sha256.lower() != verifier:
            print("ERROR: running verifier differs from the approved verifier digest; refusing to sign", file=sys.stderr)
            return 2
        _, raw_public = _load_private(Path(args.key))
        attestation = make_attestation(report, args.principal, key_id_of(raw_public), now_utc(), verifier)
        bundle.update(bundle_version=2, attestation=attestation, signature_namespace=NAMESPACE_V2,
                      signature=_signature(canonical({"statement": statement, "attestation": attestation}), Path(args.key), NAMESPACE_V2))
    elif args.key:
        print("WARNING: no --principal given; creating a legacy v1 bundle (no signing time or verifier binding). Use --principal for v2.", file=sys.stderr)
        bundle.update(signature=_signature(canonical(statement), Path(args.key)), signature_namespace=NAMESPACE)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes((json.dumps(bundle, indent=2, ensure_ascii=False) + "\n").encode("utf-8", "backslashreplace"))
    print(json.dumps({"bundle": str(output), "bundle_version": bundle["bundle_version"], "report_sha256": statement["predicate"]["report_sha256"], "signed": bool(bundle["signature"]), "note": "Unsigned bundles are NOT trusted attestations"}, indent=2))
    return 0


def verify(args: argparse.Namespace) -> int:
    """Re-verify a bundle WITHOUT re-running any test: signature, signer validity, commit, policy, verifier and (optionally) policy approval."""
    info: dict[str, Any] = {}
    try:
        bundle = _read_json(Path(args.bundle))
        errors, info = bundle_assessment(bundle, Path(args.allowed_signers), args.principal, args.expected_commit, args.expected_policy_sha256,
                                         getattr(args, "expected_verifier_sha256", None), getattr(args, "require_v2", False))
        if not errors and getattr(args, "expected_repository", None) and bundle["report"].get("repository") != args.expected_repository:
            errors.append("Repository differs from the independently expected repository")
        if getattr(args, "approval", None):
            policy = bundle.get("report", {}).get("policy_sha256") if isinstance(bundle, dict) and isinstance(bundle.get("report"), dict) else None
            aerr, ainfo = approval_assessment(_read_json(Path(args.approval)), Path(args.approvers or args.allowed_signers), args.approver_principal or args.principal, policy)
            errors += ["Policy approval: " + e for e in aerr]
            info["policy_approval"] = ainfo
        authenticated = not errors
        if authenticated and not getattr(args, "authenticate_failure", False) and bundle["report"]["overall_verdict"] != "PASS":
            errors.append("Authenticated verdict is FAIL")
    except Exception as exc:
        authenticated = False
        errors = [f"Invalid proof: {type(exc).__name__}: {exc}"]
    result = {"verified": not errors, "errors": errors, "legacy_bundle": info.get("legacy"), "signer": {"principal": info.get("principal"), "key_id": info.get("key_id"), "signed_at": info.get("signed_at")},
              "verifier_sha256": info.get("verifier_sha256"), "scope": info.get("scope") if not errors or getattr(args, "print_scope", False) else None,
              "authenticated_verdict": info.get("scope", {}).get("overall_verdict") if authenticated else None}
    if info.get("policy_approval"): result["policy_approval"] = info["policy_approval"]
    print(json.dumps(result, indent=2))
    return 0 if not errors else 1


def add_commands(sub: argparse._SubParsersAction) -> None:
    state = os.environ.get("TRUSTDIFF_STATE_DIR", ".trustdiff")
    for name, sign in [("bundle", False), ("attest", True)]:
        parser = sub.add_parser(name, help="Create a portable evidence bundle" + (" signed by an external Ed25519 key" if sign else " (unsigned)"))
        parser.add_argument("--input", default=str(Path(state) / "latest.json"))
        parser.add_argument("--output", default=str(Path(state) / "proof.json"))
        if sign:
            parser.add_argument("--key", required=True, help="Ed25519 private signing key outside the target repository (requires crypto extra)")
            parser.add_argument("--principal", help="Signer identity recorded in a v2 bundle (omit for a legacy v1 bundle)")
            parser.add_argument("--require-verifier-sha256", help="Refuse to sign unless this verifier's code digest equals the approved value")
            parser.add_argument("--include-failure", action="store_true", help="Allow signing a completed fail-closed verdict with a v2 principal")
            parser.add_argument("--expected-commit")
            parser.add_argument("--expected-baseline")
            parser.add_argument("--expected-repository", type=str.lower)
            parser.add_argument("--expected-policy-sha256")
        else:
            parser.set_defaults(key=None, principal=None, require_verifier_sha256=None)
        parser.set_defaults(func=package)
    k = sub.add_parser("keygen", help="Demo Ed25519 signer setup; production keys belong to independent verifier")
    k.add_argument("--private", required=True); k.add_argument("--allowed-signers", required=True); k.add_argument("--principal", required=True)
    k.set_defaults(func=keygen)
    r = sub.add_parser("rotate-key", help="Add a new signing key for a principal and retire its previous keys")
    r.add_argument("--allowed-signers", required=True); r.add_argument("--principal", required=True); r.add_argument("--new-private", required=True)
    r.add_argument("--keep-old", action="store_true", help="Do not retire existing keys"); r.set_defaults(func=rotate_key)
    x = sub.add_parser("revoke-key", help="Hard-revoke a signing key: all its signatures stop verifying")
    x.add_argument("--allowed-signers", required=True); x.add_argument("--principal", required=True); x.add_argument("--key-id", required=True); x.add_argument("--reason", default="")
    x.set_defaults(func=revoke_key)
    v = sub.add_parser("verify-proof", help="Re-verify a proof bundle without re-running tests: signature, signer validity, commit, policy, verifier")
    v.add_argument("--bundle", required=True)
    v.add_argument("--allowed-signers", required=True, help="Trust store provisioned outside the target repo")
    v.add_argument("--principal", required=True)
    v.add_argument("--expected-commit", required=True)
    v.add_argument("--expected-policy-sha256")
    v.add_argument("--expected-repository", type=str.lower)
    v.add_argument("--expected-verifier-sha256", help="Externally approved verifier code digest (v2 bundles)")
    v.add_argument("--require-v2", action="store_true", help="Refuse legacy v1 bundles")
    verdict = v.add_mutually_exclusive_group()
    verdict.add_argument("--require-pass", action="store_true", help="Require an authenticated PASS for a merge gate (default)")
    verdict.add_argument("--authenticate-failure", action="store_true", help="Return success for a valid signed FAIL as well as PASS")
    v.add_argument("--print-scope", action="store_true", help="Show what the bundle attests even when verification fails")
    v.add_argument("--approval", help="Signed policy-approval record that must cover the report's policy digest")
    v.add_argument("--approvers", help="Trust store for approvers (default: --allowed-signers)")
    v.add_argument("--approver-principal", help="Approver identity (default: --principal)")
    v.set_defaults(func=verify)
    a = sub.add_parser("approve-policy", help="Sign an approval of a policy digest (human/organisation approver, never the agent)")
    a.add_argument("--key", required=True); a.add_argument("--principal", required=True)
    a.add_argument("--policy-sha256"); a.add_argument("--policy-file", default="trustdiff.contracts.json")
    a.add_argument("--policy-path", default="trustdiff.contracts.json"); a.add_argument("--baseline")
    a.add_argument("--reason", required=True); a.add_argument("--output", required=True)
    a.set_defaults(func=approve_policy)
    va = sub.add_parser("verify-approval", help="Verify a signed policy-approval record")
    va.add_argument("--approval", required=True); va.add_argument("--allowed-signers", required=True); va.add_argument("--principal", required=True)
    va.add_argument("--expected-policy-sha256"); va.set_defaults(func=verify_approval)
    import trustdiff_store
    import trustdiff_supply
    trustdiff_store.add_commands(sub)
    trustdiff_supply.add_commands(sub)
