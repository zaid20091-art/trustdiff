# Evidence protocol v2 (alpha)

`trustdiff check` produces `.trustdiff/latest.json` (a diagnostic JSON report) and `.trustdiff/evidence/SHA256.json` (a canonical archived report). `.trustdiff/ledger.jsonl` links verification records with a SHA-256 hash chain, and `.trustdiff/ledger.anchor.json` records the local count and latest head.

Report fields include schema/version, baseline/target Git commits, committed policy source/digest/drift, worktree fingerprint before/after, full tracked and relevant untracked input hashes, environment and execution-mode metadata, concrete contract results and their evidence IDs, claim obligations, changed files, static impact edges/affected tests, risk topics, coverage gaps, test weakening signals, suggested challenges and executed generated countertests. `overall_verdict` is `PASS` or `FAIL`; individual checks may be `PASS`, `FAIL`, `ERROR`, `UNKNOWN`, or `WAIVED` (never technical proof).

`verify-ledger` verifies per-line hashes, prior links, archived report bytes and local anchor. It cannot authenticate the entire ledger without external evidence.

## Portable statements

`trustdiff bundle` creates `.trustdiff/proof.json` only for a passing report. It contains an in-toto Statement v1 with a Git commit subject (`sha1` or `sha256` as appropriate), a TrustDiff-specific verification predicate, a SHA-256 hash of the JSON report, baseline/policy fingerprints, runner config, and the full report for offline inspection. **Unsigned bundles are unauthenticated.**

`trustdiff attest --key /outside/repo/signing.pem` creates an Ed25519 signature over `trustdiff-proof-v1@trustdiff.dev + NUL + canonical(statement)`. The signature is base64-encoded and stored alongside the statement. Keys come from `cryptography`'s Ed25519 primitives. A `--allowed-signers` JSON file maps a principal to an array of base64-encoded 32-byte Ed25519 public keys. This is a **TrustDiff-specific signature envelope**, not a DSSE envelope or a SLSA provenance predicate. It does not claim SLSA level compliance.

`verify-proof` checks the envelope signature against externally approved keys, re-derives the statement from the bundled report, validates `overall_verdict`, checks the exact `--expected-commit`, and compares an optional approved `--expected-policy-sha256`. Always use both an externally supplied commit and policy hash for deployment approval. Do not accept allowed-signers material embedded in the evaluated repository or self-issued agent signatures as independent proof.

## Replay expectations

To replay an execution one must have the same source tree, trusted baseline policy, container image digest, runner architecture, dependency resolution, environment and any required fixtures. A signed statement attests to reported results, **not** necessarily byte-for-byte reproducibility. CI artifacts are ephemeral unless retained in trusted storage.

## Consuming evidence (agents, MCP, tooling)

Use `trustdiff_evidence.validate(state_dir, repo_root, TrustAnchors)`; do not read `latest.json` directly.

| Status | Meaning | May display PASS as a verdict? |
|---|---|---|
| `VERIFIED` | Authorised Ed25519 signature, subject = current `HEAD`, bundle report == `latest.json`, clean worktree | yes |
| `UNVERIFIED` | Well-formed but no proof of origin (no anchors, no bundle, or only a consistent local ledger) | no — `claimed_verdict` only |
| `STALE_REPORT` | Report/proof is for another commit, or files changed after it | no |
| `INVALID_EVIDENCE` | Malformed, oversized, symlinked, edited after the check, or signature/binding failed | no — content withheld |
| `NOT_RUN` | No report | no |

Starting in 0.4.0, a v2 envelope can authenticate a completed failed verdict. Use
`attest --principal NAME --include-failure` on a protected verifier. Integrity,
baseline policy binding, clean checkout and execution-source requirements still
apply. `verify-proof` reports `authenticated_verdict` and keeps its default
exit-zero policy for authenticated PASS. Use `--authenticate-failure` when
the exit code should reflect authentication alone. Merge gates can specify
`--require-pass` explicitly.

## Interoperable encoding

The [v2 envelope schema](schemas/evidence-v2.schema.json) describes the wire
shape. For v2, encode the object with members `statement` and `attestation`
using Python-compatible JSON with keys sorted recursively in Unicode code
point order, separators comma and colon with no extra spaces, Unicode output
encoded as UTF-8, and non-finite numbers forbidden. Prefix those bytes with
`trustdiff-proof-v2@trustdiff.dev` followed by one NUL byte. Encode the
Ed25519 signature as standard padded base64. The report digest uses sorted
keys and the default JSON separators comma-space and colon-space. Non-UTF-8
Git names are represented as escaped surrogate code units in the report.
See `trustdiff_proof.py` for reference encoding and key validity rules.

Schema validation checks shape. Consumers also authenticate the signature,
recompute the statement, apply the key's validity windows, and provide the
expected full commit, policy digest and verifier digest independently.
Existing v1 PASS proofs can still be read unless `--require-v2` is set.
When the approved verifier supplies `--repository`, the report contains a
lowercase `owner/name` and the subject name is `git-commit:owner/name`.
Repository-aware consumers require this binding to prevent cross-repository
replay of shared commits.
